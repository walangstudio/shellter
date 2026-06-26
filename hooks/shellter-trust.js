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

function trustStorePath() {
  return process.env.SHELLTER_TRUST_FILE || path.join(os.homedir(), '.claude', 'shellter-trust.json');
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

function collectAllow(file, toolName, out) {
  try {
    const obj = JSON.parse(fs.readFileSync(file, 'utf8'));
    const allow = obj && obj.permissions && Array.isArray(obj.permissions.allow) ? obj.permissions.allow : [];
    const prefix = toolName + '(';
    for (const rule of allow) {
      if (typeof rule === 'string' && rule.startsWith(prefix) && rule.endsWith(')')) {
        out.push(rule.slice(prefix.length, -1));
      }
    }
  } catch { /* missing/corrupt -> ignore */ }
}

function claudeAllowRules(cwd, toolName) {
  if (_allowCache && _allowCache.cwd === cwd && _allowCache.tool === toolName) return _allowCache.rules;
  const rules = [];
  let dir = cwd ? path.resolve(cwd) : process.cwd();
  for (let i = 0; i < 40; i++) {
    collectAllow(path.join(dir, '.claude', 'settings.local.json'), toolName, rules);
    collectAllow(path.join(dir, '.claude', 'settings.json'), toolName, rules);
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  collectAllow(path.join(os.homedir(), '.claude', 'settings.json'), toolName, rules);
  _allowCache = { cwd, tool: toolName, rules };
  return rules;
}

function commandAllowed(cmd, cwd, toolName) {
  if (!cmd) return false;
  const c = cmd.trim();
  for (const inner of claudeAllowRules(cwd, toolName)) {
    if (inner.endsWith(':*')) {
      const pfx = inner.slice(0, -2);
      // A `:*` prefix only silences a script flag when it names a specific script
      // (contains a space or path separator). A bare-interpreter prefix like
      // `bash` or `sh` is too broad to auto-trust arbitrary script contents.
      if (!/[ \t/\\]/.test(pfx)) continue;
      if (c === pfx || c.startsWith(pfx)) return true;
    } else if (c === inner) {
      return true;
    }
  }
  return false;
}

module.exports = {
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
