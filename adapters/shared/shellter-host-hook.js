#!/usr/bin/env node
// shellter — shared external PreToolUse hook for codex and agy (Antigravity CLI).
//
// Both hosts run an external program before a tool executes, hand it a JSON
// object on stdin, and read an allow/deny verdict back. This file normalizes
// the host's payload into shellter's Claude-Code-shaped input, spawns the same
// check-bash.js / check-sensitive-files.js detector every other client uses,
// and emits the verdict in the host's expected format.
//
// Usage (in the host's hook config):
//   node /path/to/shellter-host-hook.js --host=codex
//   node /path/to/shellter-host-hook.js --host=agy
//
// Field extraction is deliberately defensive: both products are young and their
// exact key names drift between versions, so each value is read from several
// plausible paths rather than one. Unknown tools and parse failures fall open
// (never brick the host); a hard deny is only emitted on a confident match.
'use strict';
const { execFileSync } = require('child_process');
const { existsSync } = require('fs');
const path = require('path');

const host = (process.argv.find((a) => a.startsWith('--host=')) || '').split('=')[1] || 'codex';
const HOOKS =
  process.env.SHELLTER_HOOKS_DIR ||
  [
    path.join(__dirname, '..', '..', 'hooks'), // dev: adapters/shared/../../hooks
    path.join(__dirname, 'shellter-hooks'),    // installed alongside
    path.join(__dirname, '..', 'shellter-hooks'),
  ].find((d) => existsSync(d)) ||
  path.join(__dirname, '..', '..', 'hooks');
const BASH_HOOK = path.join(HOOKS, 'check-bash.js');
const FILE_HOOK = path.join(HOOKS, 'check-sensitive-files.js');

const first = (...vals) => vals.find((v) => v !== undefined && v !== null && v !== '');
const asCommand = (c) => (Array.isArray(c) ? c.join(' ') : typeof c === 'string' ? c : '');

// Host payload -> { hook, name, input } in shellter's Claude-Code shape, or null
// when this isn't a tool we gate.
function mapTool(ev) {
  const toolName = String(first(ev.tool_name, ev.toolName, ev.toolCall && ev.toolCall.name, ev.tool && ev.tool.name) || '');
  const args = first(ev.tool_input, ev.toolCall && ev.toolCall.args, ev.args, ev.input, {}) || {};
  const lname = toolName.toLowerCase();

  const isShell = /(^|[_-])(bash|sh|shell|exec|run_command|run_shell_command|run_terminal|terminal|run_code|execute)([_-]|$)/.test(lname) ||
    (args && (args.command !== undefined || args.cmd !== undefined || args.script !== undefined));
  if (isShell) {
    const command = asCommand(first(args.command, args.cmd, args.script, ''));
    if (!command) return null;
    return { hook: BASH_HOOK, name: process.platform === 'win32' ? 'PowerShell' : 'Bash', input: { command } };
  }

  const isWrite = /(write_to_file|write_file|file_write|str_replace|replace_file_content|multi_replace|create_file|update_file|apply_patch|save_file|^patch$|^write$|^edit$)/.test(lname);
  if (isWrite) {
    const file_path = String(first(args.path, args.file_path, args.target_file, args.absolute_path, args.filePath, '') || '');
    // Pull the attacker-influenced new text from whatever shape the host uses.
    let content = first(args.content, args.new_content, args.new_string, args.newText, args.text);
    if (content === undefined && Array.isArray(args.edits)) content = args.edits.map((e) => first(e && (e.newText || e.new_string || e.content), '')).join('\n');
    if (content === undefined && Array.isArray(args.replacements)) content = args.replacements.map((e) => first(e && (e.newText || e.new_string || e.content), '')).join('\n');
    // codex apply_patch / agy patch tools carry the change as one patch blob.
    if (content === undefined) content = asCommand(first(args.patch, args.input, args.changes, ''));
    return { hook: FILE_HOOK, name: 'Write', input: { file_path, content: content || '' } };
  }
  return null; // unknown / MCP tool -> fall through
}

// The shim is always invoked as `node <shim>`, so node is on PATH by definition
// (no bun/process.execPath fallback needed, unlike the in-process adapters).
function runHook(hook, name, input, cwd) {
  const payload = JSON.stringify({ tool_name: name, tool_input: input, cwd: cwd || process.cwd() });
  try {
    return execFileSync('node', [hook], { input: payload, encoding: 'utf8', timeout: 5000 });
  } catch (e) {
    if (e && e.stdout) return e.stdout.toString(); // hook printed then exited nonzero
    // True spawn failure (missing hook file, timeout, node not found). check-bash
    // emits NOTHING on a normal allow, so a clean allow also returns '' -- but it
    // does not throw. Only a thrown failure lands here, so warn loudly (still fall
    // open per shellter's never-brick-the-host policy) so the gap is diagnosable.
    process.stderr.write('[shellter] detector did NOT run (' + ((e && (e.code || e.message)) || 'unknown') + ') -- command NOT screened: ' + hook + '\n');
    return '';
  }
}

function decide(out) {
  try {
    const h = JSON.parse(out).hookSpecificOutput;
    return { decision: (h && h.permissionDecision) || 'allow', reason: (h && h.permissionDecisionReason) || '' };
  } catch {
    return { decision: 'allow', reason: '' };
  }
}

// Emit the verdict in the host's format, then exit.
function emit(decision, reason) {
  if (host === 'agy') {
    // agy honors deny / ask / allow with a reason. Only speak up on deny/ask.
    if (decision === 'deny' || decision === 'ask') {
      process.stdout.write(JSON.stringify({ decision, reason }));
    }
    process.exit(0);
  }
  // codex: PreToolUse only acts on "deny". For "ask" we surface shellter's reason
  // on stderr (so the human sees WHY it's borderline) but let codex's own approval
  // prompt make the call -- emitting "ask" as a verdict would be ignored anyway.
  if (decision === 'ask') process.stderr.write('[shellter] flagged for your approval: ' + reason + '\n');
  if (decision === 'deny') {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: reason },
    }));
  }
  process.exit(0);
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (d) => { raw += d; });
process.stdin.on('end', () => {
  let ev;
  try { ev = JSON.parse(raw); } catch { process.exit(0); } // unparseable -> fall open
  const m = mapTool(ev || {});
  if (!m) process.exit(0);
  const { decision, reason } = decide(runHook(m.hook, m.name, m.input, ev.cwd || (ev.workspacePaths && ev.workspacePaths[0])));
  emit(decision, reason);
});
