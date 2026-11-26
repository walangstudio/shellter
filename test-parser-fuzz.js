#!/usr/bin/env node
// Differential fuzz of the bash parser against real bash. Property: every command bash runs is a
// command the model saw, with the same argv. One-directional: the parser refusing a string, or the
// model listing a command bash did not run, is fine.
//
// Every command word in the alphabet is the shell function `p`, which prints its argc and argv to
// fd 3; `true` is a function too. PATH is empty and the alphabet has no redirection characters and
// no other command names, so a generated string cannot run a program or write a file. One bash
// process evaluates every case, each in its own subshell, in an empty directory.
//
//   node test-parser-fuzz.js [cases] [seed]      BASH_EXE=<path> [BASH_ARGS="-e bash"] to pick the bash
// Skipped with a notice when no bash is found.
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { parseBash, walk, argvVariants } = require('./hooks/check-bash.js');

const N = +process.argv[2] || 20000;
let seed = +process.argv[3] || 1;

function findBash() {
  if (process.env.BASH_EXE) return process.env.BASH_EXE;
  // On Windows `bash` on PATH may be WSL's launcher: use Git Bash only.
  if (process.platform === 'win32') return ['C:/Program Files/Git/bin/bash.exe', 'C:/Program Files (x86)/Git/bin/bash.exe'].find((p) => fs.existsSync(p)) || null;
  // An absolute path: the run below clears PATH.
  const r = spawnSync('bash', ['-c', 'printf %s "$BASH"'], { encoding: 'utf8' });
  return r.status === 0 && r.stdout.startsWith('/') ? r.stdout : null;
}
const BASH = findBash();
if (!BASH) { console.log('test-parser-fuzz: no bash found, skipped'); process.exit(0); }
const BASH_ARGS = (process.env.BASH_ARGS || '').split(' ').filter(Boolean);
// The model is bash 4+ (macOS ships 3.2, which quotes `${ }` arguments differently).
const major = +spawnSync(BASH, [...BASH_ARGS, '-c', 'echo ${BASH_VERSINFO[0]}'], { encoding: 'utf8' }).stdout;
if (!(major >= 4)) { console.log('test-parser-fuzz: bash ' + (major || '?') + ' is older than 4, skipped'); process.exit(0); }

const rnd = (n) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
const ATOMS = ['p', 'p', 'p', ' ', ' ', ' ', 'a', 'b', '-x', ';', ';', '\n', '{', '}', ',', '..', '1', '3', '"', "'", '\\', '$', '${x', ':-', ':=', '=',
  '$x', '$y', 'x=', 'y="-x b"', 'x="a  b"', '$(', ')', '`', '#', '\r', '\r\n', '\\\n', "$'", '\\0', '\\x41', '\\r', '*', '[', ']', '$((', '))', '+', '&&', '||', '!',
  '~', '%', '/', '"$x"', '{a,b}', '{1..3}', '{a,{b,c}}', '${x:-{}', '${x:-"}"}', 'for i in', 'do', 'done', 'if', 'then', 'fi', 'true'];
// Every shape the 0.11.0 reviews found, as fixed seeds.
const SEEDS = ['p ${x:-{} ; p b #}', 'p a \\\r\np b', 'p {-x,a}', "p $'a\\0b' c", 'x="-x b"; p $x', 'x="a b"; p "$x" $x', 'p a # c \\\np b', 'p {1..3}',
  'p a{b,c}d', 'for i in {1..2}; do p $i; done', "p '{a,b}' \"{a,b}\"", 'x=; : ${x:=a b}; p $x', 'p ${x:-"}"} b', 'p "${x:-$y}"', 'p ${x:-a b}',
  'x=a; p {$x,b}', 'p {a,b}{c,d}', 'p {,}', 'p a{,}', 'p {01..3}', 'p {a..c}', 'x="a b"; for i in $x; do p $i; done', 'p a\r', 'p `p a`', 'p $(p a) b'];
const cases = [...SEEDS];
while (cases.length < N) { let s = 'p '; for (let k = 2 + rnd(9); k > 0; k--) s += ATOMS[rnd(ATOMS.length)]; cases.push(s); }

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'shellter-fuzz-'));
const empty = path.join(work, 'cwd');
fs.mkdirSync(empty);
fs.writeFileSync(path.join(work, 'cases'), cases.join('\0') + '\0');
fs.writeFileSync(path.join(work, 'run.sh'), [
  'exec 3>&1',
  'p() { printf "%s\\037" "$#" "$@" >&3; printf "\\036" >&3; }',
  'true() { :; }',
  'cd cwd',
  'PATH= HOME=/fuzzhome',
  'while IFS= read -r -d "" c; do ( trap wait EXIT; eval "$c" ) >/dev/null 2>&1 </dev/null; printf "\\035"; done < ../cases',
  '',
].join('\n'));
const r = spawnSync(BASH, [...BASH_ARGS, '--norc', '--noprofile', 'run.sh'], { cwd: work, env: { PATH: '' }, encoding: 'latin1', maxBuffer: 1 << 28, timeout: 600000 });
try { fs.rmSync(work, { recursive: true, force: true, maxRetries: 5 }); } catch (_) { /* a WSL bash may still hold the directory */ }
if (r.error) { console.error(r.error); process.exit(2); }
const outs = r.stdout.split('\x1d');

// Model token per word: exact literal, one argument of any text, or any number of arguments
// (an unquoted expansion the model could not resolve may split or vanish).
const kind = (w) => (w.text === '_derived_' && w.lit ? 'many' : w.lit && !w.arith ? 'exact' : w.uexp || w.bare !== false ? 'many' : 'one');
// A bare leading `~` before `/`, `:` or the end is the home directory (run.sh sets HOME). The deny
// rules and W-1 read `~` as home already, so the parser keeps it.
const text = (w) => (w.bare !== false && /^~(?=[/:]|$)/.test(w.text) ? '/fuzzhome' + w.text.slice(1) : w.text);
function fits(model, real, i = 0, j = 0) {
  if (i === model.length) return j === real.length;
  const w = model[i], k = kind(w);
  if (k === 'many') { for (let e = j; e <= real.length; e++) if (fits(model, real, i + 1, e)) return true; return false; }
  return j < real.length && (k === 'one' || text(w) === real[j]) && fits(model, real, i + 1, j + 1);
}
// Every real call needs its own model call (a call inside a loop body may repeat): bipartite matching.
function matched(model, real) {
  const owner = new Array(model.length).fill(-1);
  const take = (c, seen) => {
    for (let m = 0; m < model.length; m++) {
      if (seen.has(m) || !fits(model[m].argv, real[c])) continue;
      seen.add(m);
      if (model[m].loop) return true;
      if (owner[m] === -1 || take(owner[m], seen)) { owner[m] = c; return true; }
    }
    return false;
  };
  for (let c = 0; c < real.length; c++) if (!take(c, new Set())) return c;
  return -1;
}
function inLoops(l, acc, loop) {
  for (const p of l.items) for (const st of p.stages) {
    if (loop) acc.add(p);
    const kids = st.type === 'for' || st.type === 'loop' ? [[st.body, true], ...(st.cond ? [[st.cond, true]] : [])]
      : st.type === 'if' ? st.parts.map((x) => [x, loop]) : st.type === 'case' ? st.arms.map((x) => [x.body, loop])
        : st.type === 'group' || st.type === 'subshell' ? [[st.body, loop]] : [];
    for (const [b, lp] of kids) inLoops(b, acc, lp);
    for (const w of [...(st.words || []), ...((st.redirs || []).map((x) => x.target).filter(Boolean))]) for (const s of w.subs || []) inLoops(s, acc, loop);
  }
  return acc;
}

let bad = 0, parsed = 0;
for (let k = 0; k < cases.length; k++) {
  const real = (outs[k] || '').split('\x1e').filter((x) => x !== '').map((c) => c.split('\x1f').slice(0, -1)).map((f) => ['p', ...f.slice(1)]);
  const ast = parseBash(cases[k]);
  if (!ast) continue;
  parsed++;
  const loops = inLoops(ast, new Set(), false);
  const model = [];
  try {
    walk(ast, new Map(), (pl, v) => {
      for (const st of pl.stages) if (st.type === 'simple' && st.words.length) for (const argv of argvVariants(st.words, v)) model.push({ argv, loop: loops.has(pl) });
      return true;
    }, false);
  } catch (e) { continue; }
  const miss = matched(model, real);
  if (miss !== -1) {
    bad++;
    if (bad <= 30) console.log('MISMATCH ' + JSON.stringify(cases[k]) + '  bash ran ' + JSON.stringify(real[miss]) + '  model saw ' +
      JSON.stringify(model.map((m) => m.argv.map((w) => (kind(w) === 'exact' ? w.text : '<' + kind(w) + '>')))));
  }
}
console.log('=== parser fuzz: ' + cases.length + ' cases, ' + parsed + ' parsed, ' + bad + ' mismatching ===');
process.exit(bad ? 1 : 0);
