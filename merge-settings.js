#!/usr/bin/env node
// Merges hook configuration into an existing ~/.claude/settings.json.
// Safe to run multiple times -- overwrites only "permissions" and "hooks" keys.
//
// Usage: node merge-settings.js [path-to-settings.json]
// Default: ~/.claude/settings.json

'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');

const targetPath = process.argv[2]
  || path.join(os.homedir(), '.claude', 'settings.json');

const templatePath = path.join(__dirname, 'settings-template.json');

if (!fs.existsSync(templatePath)) {
  console.error('Template not found:', templatePath);
  process.exit(1);
}

const template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));

// Fix paths in template to match current user's home directory
// Normalize to forward slashes for Windows compatibility in JSON
const homeDir = os.homedir().replace(/\\/g, '/');
const templateStr = JSON.stringify(template).replace(/\/home\/nino/g, homeDir);
const fixedTemplate = JSON.parse(templateStr);

let existing = {};
if (fs.existsSync(targetPath)) {
  try {
    existing = JSON.parse(fs.readFileSync(targetPath, 'utf8'));
    console.log('Found existing settings at', targetPath);
  } catch (e) {
    console.error('Failed to parse existing settings, backing up and starting fresh');
    fs.copyFileSync(targetPath, targetPath + '.bak');
    existing = {};
  }
} else {
  // Ensure directory exists
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });
  console.log('No existing settings found, creating new file');
}

// Merge: template keys overwrite existing for permissions and hooks only
existing.permissions = fixedTemplate.permissions;
existing.hooks = fixedTemplate.hooks;

fs.writeFileSync(targetPath, JSON.stringify(existing, null, 2) + '\n');
console.log('Merged permissions and hooks into', targetPath);
console.log('Hook paths set to:', homeDir + '/.claude/hooks/');

// Verify hooks exist
const hooksDir = path.join(homeDir, '.claude', 'hooks');
const bashHook = path.join(hooksDir, 'check-bash.js');
const filesHook = path.join(hooksDir, 'check-sensitive-files.js');

if (!fs.existsSync(bashHook)) {
  console.warn('WARNING: Hook not found:', bashHook);
  console.warn('  Copy it: cp hooks/check-bash.js ~/.claude/hooks/');
}
if (!fs.existsSync(filesHook)) {
  console.warn('WARNING: Hook not found:', filesHook);
  console.warn('  Copy it: cp hooks/check-sensitive-files.js ~/.claude/hooks/');
}
