#!/usr/bin/env node
// Merges hook configuration into ~/.claude/settings.json. Idempotent --
// overwrites only "permissions" and "hooks" keys.
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

existing.permissions = fixedTemplate.permissions;
existing.hooks = fixedTemplate.hooks;

fs.writeFileSync(targetPath, JSON.stringify(existing, null, 2) + '\n');
console.log('Merged permissions and hooks into', targetPath);
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
