#!/usr/bin/env node
// Prompt-rate gate on real usage. Replays every unique Bash/PowerShell command from the decision
// log through a base ref's hooks and the working tree's hooks, and reports verdict moves.
//
//   node scripts/replay-corpus.js --base <ref> [--log <jsonl>] [--triage <json>] [--out <json>] [--only-moved <json>]
//
// --log         decision log (default $CLAUDE_HOOK_LOG or ~/.claude/shellter-decisions.jsonl)
// --triage      { "<row id>": "attack" | "accepted:<class>" | "regression" } (default .corpus-triage.json, gitignored)
// --out         where to write every row (default <tmp>/shellter-replay.json)
// --only-moved  re-run only the rows that moved in a previous --out file
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

const args = {};
for (let i = 2; i < process.argv.length; i += 2) args[process.argv[i].replace(/^--/, '')] = process.argv[i + 1];
if (!args.base) { console.error('usage: node scripts/replay-corpus.js --base <ref> [--log f] [--triage f] [--out f] [--only-moved f]'); process.exit(2); }
const ROOT = path.join(__dirname, '..');
const logFile = args.log || process.env.CLAUDE_HOOK_LOG || path.join(os.homedir(), '.claude', 'shellter-decisions.jsonl');
const triageFile = args.triage || path.join(ROOT, '.corpus-triage.json');
const outFile = args.out || path.join(os.tmpdir(), 'shellter-replay.json');

const baseDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shellter-base-'));
for (const f of ['check-bash.js', 'scan-content.js', 'shellter-trust.js']) {
  fs.writeFileSync(path.join(baseDir, f), execFileSync('git', ['-C', ROOT, 'show', args.base + ':hooks/' + f]));
}
const HOOK = { base: path.join(baseDir, 'check-bash.js'), work: path.join(ROOT, 'hooks', 'check-bash.js') };
const env = { ...process.env };
delete env.CLAUDE_HOOK_LOG;
delete env.CLAUDE_HOOK_DEBUG;

function run(which, cmd, tool) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [HOOK[which]], { env });
    let out = '', done = false;
    const t = setTimeout(() => { if (!done) { done = true; p.kill(); resolve('timeout'); } }, 20000);
    p.stdout.on('data', (d) => { out += d; });
    p.on('close', (code) => {
      if (done) return;
      done = true; clearTimeout(t);
      if (code !== 0) return resolve('exit' + code);
      if (!out.trim()) return resolve('fallthrough');
      try { resolve(JSON.parse(out).hookSpecificOutput.permissionDecision); } catch { resolve('bad'); }
    });
    p.stdin.on('error', () => {});
    p.stdin.end(JSON.stringify({ tool_name: tool, tool_input: { command: cmd }, permission_mode: 'default', cwd: ROOT }));
  });
}

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
      if (++finished % 100 === 0) process.stderr.write(finished + '/' + cmds.length + ' ' + Math.round((Date.now() - t0) / 1000) + 's\n');
    }
  };
  await Promise.all(Array.from({ length: 12 }, worker));
  fs.writeFileSync(outFile, JSON.stringify(rows));
  fs.rmSync(baseDir, { recursive: true, force: true });

  const triage = fs.existsSync(triageFile) ? JSON.parse(fs.readFileSync(triageFile, 'utf8')) : {};
  const table = {};
  for (const r of rows) { const k = r.o + ' -> ' + r.n; table[k] = (table[k] || 0) + 1; }
  console.log('rows: ' + rows.length + '  (written to ' + outFile + ')');
  for (const k of Object.keys(table).sort()) console.log('  ' + k.padEnd(28) + table[k]);

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
  const sedMoved = moved.filter((r) => /\bsed\b/.test(r.c) && triage[id(r)] !== 'attack').length;
  console.log('\ntriage tags: ' + JSON.stringify(byTag) + '  non-attack sed rows moved: ' + sedMoved);
  if (bad || sedMoved) { console.log('GATE FAILED: ' + bad + ' untriaged/regression rows, ' + sedMoved + ' sed rows'); process.exit(1); }
  console.log('GATE OK');
})();
