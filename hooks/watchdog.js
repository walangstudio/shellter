'use strict';
// A hook always answers. The analysis runs on a worker thread; the main thread only reads stdin and
// waits. When the worker has no verdict within the budget, or throws, the main thread answers with
// the timeout verdict. JavaScript cannot interrupt a regex, so a cooperative time check could not
// give this guarantee. SHELLTER_INLINE=1 runs the analysis on the main thread (the in-process test
// runners stub stdin, stdout and exit).
const fs = require('fs');
const path = require('path');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// An ask is silent in bypassPermissions / auto, so the timeout verdict there is deny. To let an
// unanalysed command run there instead, set quiet to '' (fall through).
const TIMEOUT_DECISION = { default: 'ask', quiet: 'deny' };
// Two attempts plus the allow-rule check (its git calls share ALLOW_CHECK_MS) stay under the adapters'
// 25 s kill (ADAPTER_TIMEOUT_MS in adapters/) with 5 s to spare, so no budget setting makes an
// adapter fail open.
const BUDGET_MAX_MS = 8000;
const ALLOW_CHECK_MS = 4000;
// A small input only times out from machine load: it gets one more attempt. Adversarial padding
// would time out again, so a large one does not.
const RETRY_MAX_BYTES = 16 * 1024;

function readStdin(cb) {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { data += c; });
  process.stdin.on('end', () => cb(data));
}

// The user's own allow for a command the hook could not analyse: an exact `Bash(<command>)` rule, a
// prefix rule over a single command (a prefix must cover every segment, so no separators), or a
// trusted script run as `<interpreter> <script>`. Same sources as the script-flag path: the user's
// ~/.claude/settings.json and an untracked .claude/settings.local.json. Linear regexes and bounded
// reads only: this runs outside the worker.
function userAllowed(inp) {
  const tool = inp && inp.tool_name, cmd = inp && inp.tool_input && inp.tool_input.command;
  if (!/^(?:Bash|PowerShell)$/.test(tool) || typeof cmd !== 'string' || !cmd.trim()) return false;
  const cwd = typeof inp.cwd === 'string' && inp.cwd ? inp.cwd : process.cwd();
  try {
    const trust = require('./shellter-trust.js');
    trust.setGitDeadline(Date.now() + ALLOW_CHECK_MS);
    if (trust.commandAllowed(cmd, cwd, tool, true)) return true;
    // PowerShell runs ( ), { } and @( ) inside an argument too.
    if (/[;&|<>`\n\r]|\$\(/.test(cmd) || (tool === 'PowerShell' && /[(){}@]/.test(cmd))) return false;
    if (trust.commandAllowed(cmd, cwd, tool)) return true;
    const m = /^\s*(?:bash|sh|zsh|node|python3?|pwsh|powershell)(?:\.exe)?\s+([^\s'"$-][^\s'"$]*)\s*$/i.exec(cmd);
    if (!m) return false;
    const abs = path.resolve(cwd, m[1]);
    return fs.statSync(abs).isFile() && trust.isTrusted(trust.sha256OfFileBounded(abs));
  } catch { return false; }
}

// Main thread: run `file` on a worker and answer for it. Returns true when the caller must stop.
function parent(file, hookName) {
  if (!isMainThread || process.env.SHELLTER_INLINE === '1') return false;
  readStdin((data) => {
    let done = false;
    const end = (out) => { if (done) return; done = true; if (out) process.stdout.write(out + '\n'); process.exit(0); };
    // Counted from the worker's first line, so a slow process start is not charged.
    const budget = Math.min(BUDGET_MAX_MS, Math.max(1000, parseInt(process.env.SHELLTER_BUDGET_MS, 10) || BUDGET_MAX_MS));
    const unanswered = (why) => {
      let inp = {};
      try { inp = JSON.parse(data.replace(/^﻿/, '')) || {}; } catch { /* default mode */ }
      const allowed = userAllowed(inp);
      const decision = allowed ? '' : /^(?:bypassPermissions|auto)$/.test(inp.permission_mode) ? TIMEOUT_DECISION.quiet : TIMEOUT_DECISION.default;
      let reason = 'shellter (' + hookName + ') could not finish analysing this ' + why + ' -- retry, or split the command into smaller steps';
      if (/^(?:Bash|PowerShell)$/.test(inp.tool_name)) {
        const t = inp.tool_name;
        reason += '. To let it run without analysis next time, add "' + t + '(<this exact command>)" to permissions.allow in ' +
          '~/.claude/settings.json or in this project\'s untracked .claude/settings.local.json; a single command (no ; & | or redirect) ' +
          'can use a prefix rule "' + t + '(<command and first argument>:*)"; a script run as "bash <script>" can be trusted with ' +
          '"node ~/.claude/hooks/shellter-trust.js add <script>"';
      }
      const log = process.env.CLAUDE_HOOK_LOG;
      if (log) try { fs.appendFileSync(log, JSON.stringify({ ts: new Date().toISOString(), hook: hookName, decision: decision || 'fallthrough', reason: allowed ? 'timeout, user allow rule' : reason, snippet: '' }) + '\n'); } catch { /* best effort */ }
      end(decision && JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason } }));
    };
    const attempt = (retried) => {
      const w = new Worker(file, { workerData: data });
      let over = false;
      w.on('online', () => setTimeout(() => {
        over = true;
        w.terminate();
        if (!retried && Buffer.byteLength(data) < RETRY_MAX_BYTES) attempt(true);
        else unanswered('in ' + budget / 1000 + ' s' + (retried ? ', twice' : ''));
      }, budget));
      w.on('message', (m) => end(m && m.out));
      w.on('error', (e) => unanswered('(internal error: ' + String(e && e.message).slice(0, 120) + ')'));
      w.on('exit', () => { if (!over) end(''); });
    };
    attempt(false);
  });
  return true;
}

// The hook's input: workerData on a worker, stdin otherwise.
function input(cb) {
  if (isMainThread) readStdin(cb); else cb(workerData);
}

// The hook's verdict: posted to the main thread from a worker, written to stdout otherwise.
function finish(output) {
  if (isMainThread) process.stdout.write(output + '\n'); else parentPort.postMessage({ out: output });
  process.exit(0);
}

module.exports = { parent, input, finish, TIMEOUT_DECISION, BUDGET_MAX_MS, ALLOW_CHECK_MS, RETRY_MAX_BYTES };
