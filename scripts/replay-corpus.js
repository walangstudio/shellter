#!/usr/bin/env node
// Prompt-rate gate on real usage. Replays every unique Bash/PowerShell command from the decision
// log through a base ref's hooks and the working tree's hooks, and reports verdict moves.
//
//   node scripts/replay-corpus.js --base <ref> [--log <jsonl>] [--triage <json>] [--out <json>] [--only-moved <json>] [--spawn]
//
// --log         decision log (default $CLAUDE_HOOK_LOG or ~/.claude/shellter-decisions.jsonl)
// --triage      { "<row id>": "attack" | "accepted:<class>" | "regression" } (default .corpus-triage.json, gitignored)
// --out         where to write every row (default <tmp>/shellter-replay.json)
// --only-moved  re-run only the rows that moved in a previous --out file
// --spawn       run each hook as a child process (slow, about 45 minutes for 5,000 rows) instead of
//               in-process (about a minute). Use it to confirm the moved rows: a stubbed
//               process.exit throws, and a try/catch in a hook can swallow that throw.
//
// Exit 1 when a moved row (allow -> anything else, fallthrough -> ask/deny) is untriaged or a
// regression, or when a gain (fallthrough -> allow) is tagged attack. The log holds private
// paths, so neither it nor the triage file is ever committed.
'use strict';
const { spawn, execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

const args = {};
for (let i = 2; i < process.argv.length; i++) {
  const k = process.argv[i].replace(/^--/, '');
  if (k === 'spawn') args.spawn = true; else args[k] = process.argv[++i];
}
if (!args.base) { console.error('usage: node scripts/replay-corpus.js --base <ref> [--log f] [--triage f] [--out f] [--only-moved f] [--spawn]'); process.exit(2); }
const ROOT = path.join(__dirname, '..');
const logFile = args.log || process.env.CLAUDE_HOOK_LOG || path.join(os.homedir(), '.claude', 'shellter-decisions.jsonl');
const triageFile = args.triage || path.join(ROOT, '.corpus-triage.json');
const outFile = args.out || path.join(os.tmpdir(), 'shellter-replay.json');

const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shellter-base-'));
for (const f of ['check-bash.js', 'scan-content.js', 'shellter-trust.js']) {
  fs.writeFileSync(path.join(baseDir, f), execFileSync('git', ['-C', ROOT, 'show', args.base + ':hooks/' + f]));
}
const HOOK = { base: path.join(baseDir, 'check-bash.js'), work: path.join(ROOT, 'hooks', 'check-bash.js') };
delete process.env.CLAUDE_HOOK_LOG;   // or the replay writes into the log it reads
delete process.env.CLAUDE_HOOK_DEBUG;
const payload = (cmd, tool) => JSON.stringify({ tool_name: tool, tool_input: { command: cmd }, permission_mode: 'default', cwd: ROOT });
const decision = (out) => {
  if (!out.trim()) return 'fallthrough';
  try { return JSON.parse(out).hookSpecificOutput.permissionDecision; } catch { return 'bad'; }
};

function runSpawn(which, cmd, tool) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [HOOK[which]], { env: process.env });
    let out = '', done = false;
    const t = setTimeout(() => { if (!done) { done = true; p.kill(); resolve('timeout'); } }, 20000);
    p.stdout.on('data', (d) => { out += d; });
    p.on('close', (code) => {
      if (done) return;
      done = true; clearTimeout(t);
      resolve(code !== 0 ? 'exit' + code : decision(out));
    });
    p.stdin.on('error', () => {});
    p.stdin.end(payload(cmd, tool));
  });
}

// A fresh copy of the hook per command, with stdin / stdout / exit stubbed: about 5 ms a row.
const EXIT = { exit: true };
const source = {};
function runInProcess(which, cmd, tool) {
  const hook = HOOK[which];
  const handlers = {};
  const fakeStdin = { setEncoding() {}, on(ev, fn) { handlers[ev] = fn; return fakeStdin; } };
  let out = '';
  const realExit = process.exit, realWrite = process.stdout.write;
  const stdinDesc = Object.getOwnPropertyDescriptor(process, 'stdin');
  Object.defineProperty(process, 'stdin', { value: fakeStdin, configurable: true });
  // The first exit ends the run, as it would in a real process: a try/catch in the hook can
  // swallow the stub's throw, so anything written after it is ignored.
  let exited = false;
  process.exit = () => { exited = true; throw EXIT; };
  process.stdout.write = (c) => { if (!exited) out += c; return true; };
  let res = null;
  try {
    const m = new Module(hook, null);
    m.filename = hook;
    m.paths = Module._nodeModulePaths(path.dirname(hook));
    source[hook] = source[hook] || fs.readFileSync(hook, 'utf8').replace(/^#!.*/, '');
    try {
      m._compile(source[hook], hook);
      handlers.data(payload(cmd, tool));
      handlers.end();
    } catch (e) {
      if (e !== EXIT) res = 'throw';
    }
  } finally {
    process.exit = realExit;
    process.stdout.write = realWrite;
    Object.defineProperty(process, 'stdin', stdinDesc);
  }
  return Promise.resolve(res || decision(out));
}
const run = args.spawn ? runSpawn : runInProcess;

let cmds;
if (args['only-moved']) {
  cmds = JSON.parse(fs.readFileSync(args['only-moved'], 'utf8')).filter((r) => r.o !== r.n).map((r) => r.c);
} else {
  const seen = new Set();
  for (const line of fs.readFileSync(logFile, 'utf8').split('\n')) {
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (!r || r.hook !== 'check-bash' || !/^(?:allow|fallthrough)$/.test(r.decision)) continue;
    if (typeof r.snippet === 'string' && r.snippet.length < 500) seen.add(r.snippet);   // the log truncates at 500
  }
  cmds = [...seen];
}

const id = (r) => crypto.createHash('sha1').update(r.tool + '\0' + r.c).digest('hex').slice(0, 12);
(async () => {
  const rows = new Array(cmds.length);
  let next = 0, finished = 0;
  const t0 = Date.now();
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= cmds.length) return;
      const c = cmds[i];
      let tool = 'Bash', o = await run('base', c, 'Bash');
      if (o !== 'allow') {                   // the log has no tool name
        const p = await run('base', c, 'PowerShell');
        if (p === 'allow') { tool = 'PowerShell'; o = p; }
      }
      rows[i] = { c, tool, o, n: await run('work', c, tool) };
      if (++finished % 500 === 0) process.stderr.write(finished + '/' + cmds.length + ' ' + Math.round((Date.now() - t0) / 1000) + 's\n');
    }
  };
  await Promise.all(Array.from({ length: args.spawn ? 12 : 1 }, worker));
  fs.writeFileSync(outFile, JSON.stringify(rows));
  fs.rmSync(baseDir, { recursive: true, force: true });

  const triage = fs.existsSync(triageFile) ? JSON.parse(fs.readFileSync(triageFile, 'utf8')) : {};
  const table = {};
  for (const r of rows) { const k = (r.tool === 'PowerShell' ? 'PS ' : '') + r.o + ' -> ' + r.n; table[k] = (table[k] || 0) + 1; }
  console.log('rows: ' + rows.length + '  (' + (args.spawn ? 'spawn' : 'in-process') + ', written to ' + outFile + ')');
  for (const k of Object.keys(table).sort()) console.log('  ' + k.padEnd(31) + table[k]);

  let bad = 0;
  const byTag = {};
  const show = (title, list) => {
    if (!list.length) return;
    console.log('\n' + title + ' (' + list.length + ')');
    for (const r of list) {
      const tag = triage[id(r)] || 'UNTRIAGED';
      byTag[tag] = (byTag[tag] || 0) + 1;
      console.log('  ' + id(r) + ' ' + (r.o + '->' + r.n).padEnd(22) + tag.padEnd(22) + (r.tool === 'PowerShell' ? '[PS] ' : '') + r.c.replace(/\s+/g, ' ').slice(0, 140));
    }
  };
  const moved = rows.filter((r) => r.o !== r.n && (r.o === 'allow' || /^(?:ask|deny)$/.test(r.n)));
  const gains = rows.filter((r) => r.o === 'fallthrough' && r.n === 'allow');
  show('MOVED', moved);
  for (const r of moved) { const t = triage[id(r)]; if (!t || t === 'regression') bad++; }
  show('GAINS', gains);
  for (const r of gains) if (triage[id(r)] === 'attack') bad++;
  const psMoved = moved.filter((r) => r.tool === 'PowerShell' && !/^(?:attack|accepted)/.test(triage[id(r)] || '')).length;
  console.log('\ntriage tags: ' + JSON.stringify(byTag) + '  untriaged PowerShell rows moved: ' + psMoved);
  if (bad) { console.log('GATE FAILED: ' + bad + ' untriaged/regression rows'); process.exit(1); }
  console.log('GATE OK');
})();
