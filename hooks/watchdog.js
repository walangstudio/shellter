'use strict';
// A hook always answers. The analysis runs on a worker thread; the main thread only reads stdin and
// waits. When the worker has no verdict within the budget, or throws, the main thread answers with
// the timeout verdict. JavaScript cannot interrupt a regex, so a cooperative time check could not
// give this guarantee. SHELLTER_INLINE=1 runs the analysis on the main thread (the in-process test
// runners stub stdin, stdout and exit).
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');

// An ask is silent in bypassPermissions / auto, so the timeout verdict there is deny. To let an
// unanalysed command run there instead, set quiet to '' (fall through).
const TIMEOUT_DECISION = { default: 'ask', quiet: 'deny' };

function readStdin(cb) {
  let data = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (c) => { data += c; });
  process.stdin.on('end', () => cb(data));
}

// Main thread: run `file` on a worker and answer for it. Returns true when the caller must stop.
function parent(file, hookName) {
  if (!isMainThread || process.env.SHELLTER_INLINE === '1') return false;
  readStdin((data) => {
    let done = false;
    const end = (out) => { if (done) return; done = true; if (out) process.stdout.write(out + '\n'); process.exit(0); };
    // Counted from the worker's first line, so a slow process start is not charged.
    const budget = Math.min(30000, Math.max(1000, parseInt(process.env.SHELLTER_BUDGET_MS, 10) || 10000));
    const unanswered = (why) => {
      let mode = '';
      try { mode = JSON.parse(data.replace(/^﻿/, '')).permission_mode; } catch { /* default mode */ }
      const decision = /^(?:bypassPermissions|auto)$/.test(mode) ? TIMEOUT_DECISION.quiet : TIMEOUT_DECISION.default;
      const reason = 'shellter (' + hookName + ') could not finish analysing this ' + why + ' -- retry, or split the command into smaller steps';
      const log = process.env.CLAUDE_HOOK_LOG;
      if (log) try { require('fs').appendFileSync(log, JSON.stringify({ ts: new Date().toISOString(), hook: hookName, decision: decision || 'fallthrough', reason, snippet: '' }) + '\n'); } catch { /* best effort */ }
      end(decision && JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason } }));
    };
    const w = new Worker(file, { workerData: data });
    w.on('online', () => setTimeout(() => unanswered('in ' + budget / 1000 + ' s'), budget));
    w.on('message', (m) => end(m && m.out));
    w.on('error', (e) => unanswered('(internal error: ' + String(e && e.message).slice(0, 120) + ')'));
    w.on('exit', () => end(''));
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

module.exports = { parent, input, finish, TIMEOUT_DECISION };
