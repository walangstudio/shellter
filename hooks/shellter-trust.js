#!/usr/bin/env node
'use strict';
// shellter trust store + native-allow-rule reader.
//
// Trust store: ~/.claude/shellter-trust.json (override with SHELLTER_TRUST_FILE),
// a flat map keyed by the sha256 of a script's first TRUST_SCAN_BYTES bytes:
//   { "<sha256>": { "path": "/abs/script.sh", "addedAt": "ISO" } }
// Content-hash keying means a trusted script stays trusted if moved/renamed, but
// editing it (changing the scanned window) invalidates trust and re-flags it.
//
// Native-allow honoring: lets a user's Claude Code "Yes, don't ask again" rule
// (Bash(...) / PowerShell(...)) also silence the script flag. Match is
// deliberately conservative (exact or `:*` prefix) -- narrower than Claude's own
// matcher is safe here because the fallback is "ask", not "allow".

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const TRUST_SCAN_BYTES = 256 * 1024;

// SHELLTER_TRUST_FILE counts only as an absolute path outside the working directory and outside
// any git checkout: a relative one, or one a repo ships (from any subdirectory), would let a cloned
// repo bring its own trust store.
function insideGitCheckout(p) {
  for (let d = path.dirname(p), i = 0; i < 64; i++) {
    if (fs.existsSync(path.join(d, '.git'))) return true;
    const up = path.dirname(d);
    if (up === d) return false;
    d = up;
  }
  return true;
}
function trustStorePath() {
  const env = process.env.SHELLTER_TRUST_FILE;
  if (env && path.isAbsolute(env)) {
    const rel = path.relative(process.cwd(), env);
    if ((rel.startsWith('..') || path.isAbsolute(rel)) && !insideGitCheckout(env)) return env;
  }
  return path.join(os.homedir(), '.claude', 'shellter-trust.json');
}

function readTrustStore() {
  try {
    const raw = fs.readFileSync(trustStorePath(), 'utf8');
    const obj = JSON.parse(raw);
    return obj && typeof obj === 'object' && !Array.isArray(obj) ? obj : {};
  } catch {
    return {};
  }
}

function writeTrustStore(store) {
  const dest = trustStorePath();
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const json = JSON.stringify(store, null, 2) + '\n';
  const tmp = dest + '.' + process.pid + '.tmp';
  try {
    fs.writeFileSync(tmp, json);
    fs.renameSync(tmp, dest);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch {}
    fs.writeFileSync(dest, json); // fallback when rename is blocked (AV/lock)
  }
}

function isTrusted(hash, store) {
  if (!hash) return false;
  store = store || readTrustStore();
  return Object.prototype.hasOwnProperty.call(store, hash);
}

// Hash the scanned window AND the full file size, so appending malicious content
// past the 256KB scan boundary changes the hash and invalidates trust.
function sha256OfScan(buf, size) {
  return crypto.createHash('sha256').update(String(size) + ':').update(buf).digest('hex');
}

function sha256OfFileBounded(absPath) {
  const fd = fs.openSync(absPath, 'r');
  try {
    const buf = Buffer.alloc(TRUST_SCAN_BYTES);
    const n = fs.readSync(fd, buf, 0, TRUST_SCAN_BYTES, 0);
    const size = fs.fstatSync(fd).size;
    return sha256OfScan(buf.subarray(0, n), size);
  } finally {
    fs.closeSync(fd);
  }
}

function addPath(p) {
  const abs = path.resolve(p);
  const hash = sha256OfFileBounded(abs);
  const store = readTrustStore();
  store[hash] = { path: abs, addedAt: new Date().toISOString() };
  writeTrustStore(store);
  return hash;
}

function removeKey(k) {
  if (!k) return 0;
  const store = readTrustStore();
  let removed = 0;
  for (const hash of Object.keys(store)) {
    if (hash === k || (k.length >= 8 && hash.startsWith(k)) || store[hash].path === k || store[hash].path === path.resolve(k)) {
      delete store[hash];
      removed++;
    }
  }
  if (removed) writeTrustStore(store);
  return removed;
}

function listEntries() {
  const store = readTrustStore();
  return Object.entries(store).sort((a, b) => String(a[1].addedAt).localeCompare(String(b[1].addedAt)));
}

// ---- native Claude Code allow-rule honoring ---------------------------------

let _allowCache = null;

function collectAllow(file, toolName, out, dir) {
  try {
    const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
    const allow = obj && obj.permissions && Array.isArray(obj.permissions.allow) ? obj.permissions.allow : [];
    const prefix = toolName + '(';
    for (const rule of allow) {
      if (typeof rule === 'string' && rule.startsWith(prefix) && rule.endsWith(')')) {
        out.push({ inner: rule.slice(prefix.length, -1), dir });
      }
    }
  } catch { /* missing/corrupt -> ignore */ }
}

function claudeAllowRules(cwd, toolName) {
  if (_allowCache && _allowCache.cwd === cwd && _allowCache.tool === toolName) return _allowCache.rules;
  const rules = [];
  let dir = cwd ? path.resolve(cwd) : process.cwd();
  for (let i = 0; i < 40; i++) {
    // Only settings.local.json (user-authored, where "don't ask again" lands) is honored for
    // script-flag suppression -- NOT the committed project settings.json, which a cloned
    // malicious repo controls. A settings.local.json the repo commits is ignored too
    // (checked lazily, see localRulesHonoured).
    collectAllow(path.join(dir, '.claude', 'settings.local.json'), toolName, rules, dir);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  // os.homedir() THROWS with no resolvable home (container uid w/o passwd entry); this runs on the
  // hook hot path (commandAllowed), so an unguarded throw would crash the hook and FAIL OPEN.
  let homeDir = '';
  try { homeDir = os.homedir(); } catch (_) { /* no resolvable home -> skip the user-global allow list */ }
  if (homeDir) collectAllow(path.join(homeDir, '.claude', 'settings.json'), toolName, rules);
  _allowCache = { cwd, tool: toolName, rules };
  return rules;
}

// A settings.local.json outside any git checkout is the user's own (`~/.claude`, a scratch dir):
// honoured. Inside a checkout it is honoured only when git positively says the repo does not ship
// it: exit 0 and no entry, for the file in any letter case (the file system is case-insensitive on
// Windows and macOS) and for `.claude` itself (a tracked symlink or submodule). A git error, a
// timeout, or GIT_* steering the call elsewhere -> not honoured. Runs only when a rule from that
// file matches a flagged script, so the hot path never spawns git.
const _honoured = new Map();
// The watchdog's allow check sets a deadline for all git calls together; past it a directory is not
// honoured (and not cached).
let gitDeadline = Infinity;
function setGitDeadline(at) { gitDeadline = at; }
function localRulesHonoured(dir) {
  if (!_honoured.has(dir)) {
    if (gitDeadline - Date.now() < 50) return false;
    let ok = !insideGitCheckout(path.join(dir, '.claude', 'settings.local.json'));
    if (!ok) try {
      const env = {};
      for (const [k, v] of Object.entries(process.env)) if (!/^GIT_/i.test(k)) env[k] = v;
      const ls = (spec) => require('child_process').spawnSync('git', ['-C', dir, 'ls-files', '-z', '--', spec], { env, encoding: 'utf8', timeout: Math.max(1, Math.min(2000, gitDeadline - Date.now())), maxBuffer: 16 * 1024 * 1024 });
      const file = ls(':(icase).claude/settings.local.json');
      const top = ls(':(icase).claude');
      ok = file.status === 0 && file.stdout === '' && top.status === 0 &&
        !top.stdout.split('\0').some((e) => e.toLowerCase() === '.claude');
      // An alias of the file (`CLAUDE~1/`, a trailing dot or space, an ignorable character) is
      // tracked under another name: resolve every entry not in plain form two levels down (dir/file,
      // the only shape that can name it).
      if (ok) {
        const all = ls(':(glob)*/*');
        const odd = all.status === 0 ? all.stdout.split('\0').filter((e) => e.split('/').some((c) => /[~:]|[^\x00-\x7f]|[. ]$/.test(c))) : null;
        if (!odd || odd.length > 2000) ok = false;
        else {
          const real = fs.realpathSync.native(path.join(dir, '.claude', 'settings.local.json')).toLowerCase();
          ok = !odd.some((e) => {
            try { return fs.realpathSync.native(path.join(dir, e)).toLowerCase() === real; } catch (err) { return err.code !== 'ENOENT'; }
          });
        }
      }
    } catch { /* no git */ }
    _honoured.set(dir, ok);
  }
  return _honoured.get(dir);
}

// `cmd` is one command segment. `exactOnly` is for the whole compound command line: a `:*`
// prefix matched against it would wave through anything chained after the prefix.
function commandAllowed(cmd, cwd, toolName, exactOnly) {
  if (!cmd) return false;
  const c = cmd.trim();
  for (const { inner, dir } of claudeAllowRules(cwd, toolName)) {
    let hit;
    if (inner.endsWith(':*')) {
      const pfx = inner.slice(0, -2);
      // A `:*` prefix only silences a script flag when it names a specific script
      // (contains a space or path separator). A bare-interpreter prefix like
      // `bash` or `sh` is too broad to auto-trust arbitrary script contents.
      if (exactOnly || !/[ \t/\\]/.test(pfx)) continue;
      hit = c === pfx || c.startsWith(pfx + ' ');
    } else {
      hit = c === inner;
    }
    if (hit && (!dir || localRulesHonoured(dir))) return true;
  }
  return false;
}

module.exports = {
  setGitDeadline,
  TRUST_SCAN_BYTES, trustStorePath, readTrustStore, writeTrustStore, isTrusted,
  sha256OfScan, sha256OfFileBounded, addPath, removeKey, listEntries,
  claudeAllowRules, commandAllowed,
};

// ---- CLI --------------------------------------------------------------------

if (require.main === module) {
  const [, , sub, arg] = process.argv;
  try {
    if (sub === 'add') {
      if (!arg) { console.error('usage: shellter-trust.js add <path>'); process.exit(1); }
      const hash = addPath(arg);
      console.log('trusted ' + path.resolve(arg));
      console.log('  sha256(first ' + TRUST_SCAN_BYTES + 'B) = ' + hash);
    } else if (sub === 'list') {
      const entries = listEntries();
      if (!entries.length) { console.log('(no trusted scripts)'); }
      for (const [hash, meta] of entries) {
        console.log(hash.slice(0, 12) + '  ' + (meta.addedAt || '?') + '  ' + (meta.path || '?'));
      }
    } else if (sub === 'remove' || sub === 'rm') {
      if (!arg) { console.error('usage: shellter-trust.js remove <hash|path>'); process.exit(1); }
      const n = removeKey(arg);
      console.log('removed ' + n + ' entr' + (n === 1 ? 'y' : 'ies'));
    } else {
      console.error('shellter-trust.js -- manage trusted scripts');
      console.error('  add <path>          trust a script by content hash');
      console.error('  list                list trusted scripts');
      console.error('  remove <hash|path>  remove a trust entry');
      process.exit(1);
    }
  } catch (e) {
    console.error('error: ' + (e && e.message));
    process.exit(1);
  }
}
