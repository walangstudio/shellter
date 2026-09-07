#!/usr/bin/env node
// Merges hook configuration into ~/.claude/settings.json. Idempotent --
// overwrites only the "hooks" key. It no longer touches "permissions": through
// 0.7.1 it replaced that key wholesale with file-tool wildcards, which both
// destroyed the user's own allow list and undermined the hooks it was installing.
//
// Usage: node merge-settings.js [path-to-settings.json]
// Default: ~/.claude/settings.json

'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const targetPath = process.argv[2]
  || path.join(os.homedir(), '.claude', 'settings.json');

let version = 'unknown';
try {
  version = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8')).version;
} catch {}
console.log('shellter v' + version);

const templatePath = path.join(__dirname, 'settings-template.json');

if (!fs.existsSync(templatePath)) {
  console.error('Template not found:', templatePath);
  process.exit(1);
}

const template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));

// __HOME__ -> homedir (forward-slashed for cross-platform JSON safety)
const homeDir = os.homedir().replace(/\\/g, '/');
const templateStr = JSON.stringify(template).replace(/__HOME__/g, homeDir);
const fixedTemplate = JSON.parse(templateStr);

let existing = {};
if (fs.existsSync(targetPath)) {
  try {
    existing = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
    console.log('Found existing settings at', targetPath);
  } catch (e) {
    console.error('Failed to parse existing settings, backing up to', targetPath + '.bak');
    fs.copyFileSync(targetPath, targetPath + '.bak');
    existing = {};
  }
} else {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  console.log('No existing settings found, creating new file');
}

// The template no longer carries a `permissions` block. It used to grant
// Read/Edit/Write/MultiEdit/NotebookEdit/Glob/Grep wildcards -- the exact tools
// these hooks gate -- so a hook that failed to run (node not on PATH, a crash)
// left unprompted file access behind, and every fallthrough verdict became a
// silent allow. The plugin install path never granted it, so it was pure
// asymmetric risk. This assignment also used to REPLACE the user's whole allow
// list; never touch their permissions.
if (fixedTemplate.permissions) existing.permissions = fixedTemplate.permissions;
existing.hooks = fixedTemplate.hooks;

// Removing the block from the template does nothing for anyone who already ran an
// older installer -- those wildcards are sitting in their settings.json right now,
// written there by shellter. Detect that and say so; do not edit it silently, since
// the user may have added entries of their own to the same list.
const LEGACY_WILDCARDS = ['Read(*)', 'Edit(*)', 'Write(*)', 'MultiEdit(*)',
                          'NotebookEdit(*)', 'Glob(*)', 'Grep(*)'];
const allowNow = (existing.permissions && Array.isArray(existing.permissions.allow))
  ? existing.permissions.allow : [];
const stale = LEGACY_WILDCARDS.filter((r) => allowNow.includes(r));

fs.writeFileSync(targetPath, JSON.stringify(existing, null, 2) + '\n');
console.log('Merged hooks into', targetPath);

if (stale.length >= 3) {
  console.warn('');
  console.warn('WARNING: your settings.json still allows ' + stale.join(' '));
  console.warn('  An older shellter installer (<= 0.7.1) wrote these. They blanket-approve');
  console.warn('  the exact tools these hooks gate, so if a hook ever fails to run (node not');
  console.warn('  on PATH, a crash) those file operations proceed with no prompt at all.');
  console.warn('  Remove the entries you did not add yourself from permissions.allow in:');
  console.warn('  ' + targetPath);
}
console.log('Hook paths set to:', homeDir + '/.claude/hooks/');

const hooksDir = path.join(homeDir, '.claude', 'hooks');
const bashHook = path.join(hooksDir, 'check-bash.js');
const filesHook = path.join(hooksDir, 'check-sensitive-files.js');
// Runtime deps of the two hooks above -- must be installed alongside them.
const scanHook = path.join(hooksDir, 'scan-content.js');
const trustHook = path.join(hooksDir, 'shellter-trust.js');

function sha256(p) {
  try {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

for (const p of [bashHook, filesHook, scanHook, trustHook]) {
  if (!fs.existsSync(p)) {
    console.warn('WARNING: Hook not found:', p);
    console.warn('  Copy it: cp ' + path.basename(p) + ' ' + hooksDir + '/');
    continue;
  }
  const h = sha256(p);
  if (h) console.log('  ' + path.basename(p) + '  sha256=' + h);
}

// The hooks run as `node <hook>`. Claude Code ships as a native binary with no
// bundled node, so if `node` is not on the PATH Claude Code launches with, every
// hook fails to spawn and shellter FAILS OPEN (commands run unscreened). Warn now.
try {
  const { execFileSync } = require('child_process');
  const v = execFileSync(process.platform === 'win32' ? 'node.exe' : 'node', ['--version'], { encoding: 'utf8' }).trim();
  console.log('node on PATH: ' + v + ' (required at runtime -- if Claude Code cannot find node, shellter fails open)');
} catch {
  console.warn('WARNING: `node` was not resolvable on PATH. Claude Code must be able to run `node` or the');
  console.warn('  hooks will not execute and shellter will FAIL OPEN (commands run unscreened).');
}
