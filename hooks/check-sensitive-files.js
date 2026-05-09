#!/usr/bin/env node
// PreToolUse hook for Read/Edit/Write/Glob/Grep. Blocks access to sensitive
// paths (resolves symlinks first) and detects prompt-injection / polyglot /
// invisible-character attacks in written content.
// CLAUDE_HOOK_LOG=/path or CLAUDE_HOOK_DEBUG=1 to record decisions.

'use strict';

const fs = require('fs');
const path = require('path');

function audit(decision, reason, snippet) {
  const log = process.env.CLAUDE_HOOK_LOG;
  const debug = process.env.CLAUDE_HOOK_DEBUG;
  if (!log && !debug) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    hook: 'check-sensitive-files',
    decision,
    reason,
    snippet: String(snippet || '').slice(0, 500),
  });
  if (log) {
    try { fs.appendFileSync(log, line + '\n'); } catch {}
  }
  if (debug) {
    try { process.stderr.write(line + '\n'); } catch {}
  }
}

function deny(reason, snippet) {
  audit('deny', reason, snippet);
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
  process.stdout.write(output + '\n');
  process.exit(0);
}

// Resolve symlinks for the deepest existing ancestor and re-append the
// missing tail. Avoids `ln -s ~/.env /tmp/x; Read /tmp/x` bypass.
function safeRealpath(p) {
  if (!p) return p;
  const abs = path.resolve(p);
  const parts = abs.split(path.sep);
  for (let i = parts.length; i > 0; i--) {
    const candidate = parts.slice(0, i).join(path.sep) || path.sep;
    try {
      const real = fs.realpathSync.native(candidate);
      const tail = parts.slice(i).join(path.sep);
      return tail ? path.join(real, tail) : real;
    } catch (e) {
      if (e.code !== 'ENOENT' && e.code !== 'ENOTDIR') return abs;
    }
  }
  return abs;
}

// Strip invisible/steganographic characters. Returns separate counts so callers
// can apply different policies: tag chars and bidi overrides have no legitimate
// use anywhere; zero-widths are legit in emoji ZWJ sequences but suspicious in
// source code.
function stripInvisibles(s) {
  if (typeof s !== 'string') return { clean: s, danger: 0, zwCount: 0 };
  const tagCount = (s.match(/[\u{E0000}-\u{E007F}]/gu) || []).length;
  const bidiCount = (s.match(/[‪-‮⁦-⁩]/g) || []).length;
  const zwCount = (s.match(/[​-‍⁠﻿]/g) || []).length;
  const clean = s
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/[‪-‮⁦-⁩]/g, '')
    .replace(/[​-‍⁠﻿]/g, '');
  return { clean, danger: tagCount + bidiCount, zwCount };
}

const SOURCE_LIKE_EXT = /\.(js|ts|jsx|tsx|mjs|cjs|py|rs|go|rb|java|c|cc|cpp|h|hpp|kt|swift|sh|bash|zsh|json|yaml|yml|toml|ini|html|svelte|vue|css|scss|less|sql|php|pl|lua|nim|zig)$/i;

// Prompt-injection: instruction override / role hijack phrasing.
const INJECTION_PATTERNS = [
  [/ignore\s+(all\s+)?previous\s+instructions/i, 'instruction-override phrase'],
  [/forget\s+(all\s+)?your\s+(previous\s+)?instructions/i, 'instruction-override phrase'],
  [/disregard\s+(all\s+)?(previous\s+|prior\s+)?(commands|rules|guidelines|instructions)/i, 'instruction-override phrase'],
  [/ignore\s+(everything|all)\s+(above|before)/i, 'instruction-override phrase'],
  [/override\s+system\s+prompt/i, 'instruction-override phrase'],
  [/new\s+system\s+prompt/i, 'instruction-override phrase'],
  [/\bSTOP\.\s+New\s+instruction/i, 'instruction-override phrase'],

  // Role hijacking
  [/act\s+as\s+if\s+you\s+are/i, 'role-hijack phrase'],
  [/you\s+are\s+now\s+a/i, 'role-hijack phrase'],
  [/pretend\s+(that\s+)?you\s+(are|'re)/i, 'role-hijack phrase'],
  [/assume\s+the\s+role\s+of/i, 'role-hijack phrase'],
  [/from\s+now\s+on,?\s+you\s+(are|will|must)/i, 'role-hijack phrase'],

  // Jailbreak / mode-switch
  [/you\s+have\s+been\s+(jailbroken|liberated|freed)/i, 'jailbreak phrase'],
  [/developer\s+mode\s+(on|enabled|activated)/i, 'jailbreak phrase'],
  [/\bDAN\s+mode|do\s+anything\s+now/i, 'jailbreak phrase'],

  // Role tags (chat templates)
  [/\[SYSTEM\]|\[\/?INST\]|\[ASSISTANT\]/i, 'role-tag injection'],
  [/<\|im_(start|end)\|>|<\|system\|>|<\|user\|>|<\|assistant\|>/i, 'role-tag injection'],
  [/<\/?(system|instructions?)>/i, 'role-tag injection'],
  [/###\s*(system|instruction|new\s+instruction)\s*##/i, 'role-tag injection'],
];

const HTML_INJECTION_PATTERN = /<!--\s*(system|instruction|prompt|ignore|override|you\s+are|act\s+as)/i;
const ENCODED_EVAL_PATTERN = /(eval|exec)\s*\(\s*(base64|atob|Buffer\.from)\s*\(/i;

// Fake tool-call injection (attacker-controlled file pretending to be an
// assistant message).
const TOOL_CALL_INJECTION_PATTERN = /<\/?(function_calls|invoke|tool_use|tool_call)\b|<invoke\s+name=/i;

// Markdown-rendered XSS-style URLs.
const MARKDOWN_DANGEROUS_URL = /\]\(\s*(javascript|data:text\/html|vbscript):/i;

// ANSI escape sequences in source files (terminal-display obfuscation).
const ANSI_ESCAPE_PATTERN = /\x1b\[[\d;]*[A-Za-z]/;
const ANSI_TARGET_EXTENSIONS = /\.(js|ts|jsx|tsx|py|rs|go|md|txt|json|yaml|yml|html|c|cpp|h|hpp|java|rb|sh|bash)$/i;

// Polyglot: shell command substitution in data files (NOT markdown).
const POLYGLOT_EXTENSIONS = /\.(json|yaml|yml|xml|csv|txt|toml|ini|cfg|conf)(\.(bak|old|backup|orig|tmp|swp|save))?$/i;
const POLYGLOT_PATTERN = /(\$\(|`)\s*(curl|wget|bash|sh|nc|python|perl|ruby)\b/i;

// Sensitive paths (extension-based, dir-based, env-style, secrets dirs).
// Backup suffixes (.bak, .old, .backup, .orig, .swp, .save) are matched too.
const SENSITIVE_EXTENSIONS = /\.(env|pem|key|crt|p12|pfx|jks|keystore|secret|credentials|pgpass|netrc|npmrc)(\.(bak|old|backup|orig|swp|save))?(\.\d+)?\b/i;
const SENSITIVE_DIRS = /(^|\/)(\.ssh|\.gnupg|\.aws|\.gcloud|\.azure|\.kube|\.docker\/config|\.config\/(gh|hub|gcloud)|id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)(\/|$)/i;
// .gitconfig deliberately excluded: tokens normally live in .git-credentials.
const SENSITIVE_FILES = /(^|\/)(\.git-credentials|\.npmrc|\.yarnrc|\.pnpmrc|\.pypirc|\.cargo\/credentials(\.toml)?|\.gem\/credentials|\.docker\/config\.json|\.config\/git\/credentials|\.ssh\/config|\.aws\/sso\/cache)(\/|$)/i;
const ENV_FILE = /(^|\/)\.env(\.[a-zA-Z0-9_-]+)*(\.(bak|old|backup|orig|save))?$/i;
const SECRETS_DIR = /(^|\/)(secrets?|credentials?|private[_-]?keys?)(\/|$)/i;
const SENSITIVE_GLOB = /\*\.(env|pem|key|crt|secret)/i;

// Wallet / crypto / browser cookie files.
const WALLET_PATTERN = /\b(wallet\.dat|keystore\.json|UTC--\d{4}-\d{2}-\d{2}T)\b|(^|\/)\.electrum\/wallets\/|(^|\/)\.bitcoin\/wallet\.dat$/i;
const BROWSER_DATA_PATTERN = /(Chrome|Chromium|Firefox|firefox|Edge|Safari|google-chrome|mozilla)[^\/]*\/.*\/(Cookies|Cookies-journal|Login Data|Web Data)$/;

// Grep patterns that try to extract secret values rather than do structural search.
const GREP_SECRET_EXTRACTION = [
  /(password|secret|api.?key|token|credential|private.?key)\s*[:=]\s*[^${\s]/i,
  /AKIA[0-9A-Z]{16}/,
  /gh[pousr]_[A-Za-z0-9_]{36,}/,
  /xox[bpoa]-[\w-]+/,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ/,
  /[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}/,
];

function pathMatchesAnySensitive(p) {
  if (!p) return null;
  if (SENSITIVE_EXTENSIONS.test(p)) return 'sensitive extension';
  if (SENSITIVE_DIRS.test(p)) return 'sensitive directory/file';
  if (SENSITIVE_FILES.test(p)) return 'sensitive credential file';
  if (ENV_FILE.test(p)) return '.env file';
  if (SECRETS_DIR.test(p)) return 'secrets/credentials directory';
  if (WALLET_PATTERN.test(p)) return 'wallet / crypto key file';
  if (BROWSER_DATA_PATTERN.test(p)) return 'browser cookie/login database';
  return null;
}

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { data += chunk; });
process.stdin.on('end', () => {
  let input;
  try {
    input = JSON.parse(data);
  } catch {
    process.exit(0);
  }

  const tool = input?.tool_name || '';

  // ---- content checks for Write / Edit ----
  if (tool === 'Write' || tool === 'Edit') {
    const content = tool === 'Write'
      ? (input?.tool_input?.content || '')
      : (input?.tool_input?.new_string || '');
    const filePath = input?.tool_input?.file_path || '';

    if (content) {
      const { clean, danger, zwCount } = stripInvisibles(content);
      const flat = clean.replace(/\n/g, ' ');

      const isBinary = /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|webp|ico|pdf|zip|gz|bz2|xz|7z|tar|wasm|exe|dll|so|dylib|bin|node)$/i.test(filePath);
      if (!isBinary) {
        if (danger > 0) {
          deny('Tag-character / bidi-override Unicode detected -- steganographic prompt injection', filePath);
        }
        if (zwCount > 0 && SOURCE_LIKE_EXT.test(filePath)) {
          deny('Zero-width characters in source file -- possible steganographic injection', filePath);
        }
      }

      for (const [pattern, label] of INJECTION_PATTERNS) {
        if (pattern.test(flat)) {
          deny('Prompt injection detected: ' + label, filePath);
        }
      }

      if (HTML_INJECTION_PATTERN.test(flat)) {
        deny('Possible prompt injection in HTML comment', filePath);
      }

      if (TOOL_CALL_INJECTION_PATTERN.test(flat)) {
        deny('Fake tool-call tag in written content blocked', filePath);
      }

      if (ENCODED_EVAL_PATTERN.test(flat)) {
        deny('Encoded eval/exec pattern in file content blocked', filePath);
      }

      if (MARKDOWN_DANGEROUS_URL.test(flat)) {
        deny('Markdown javascript:/data:/vbscript: URL blocked', filePath);
      }

      if (ANSI_TARGET_EXTENSIONS.test(filePath) && ANSI_ESCAPE_PATTERN.test(content)) {
        deny('ANSI escape sequence in source file blocked', filePath);
      }

      if (POLYGLOT_EXTENSIONS.test(filePath) && POLYGLOT_PATTERN.test(flat)) {
        deny('Shell command substitution in data file blocked', filePath);
      }
    }
  }

  // ---- extract the path to check ----
  let filePath = '';

  switch (tool) {
    case 'Read':
    case 'Edit':
    case 'Write':
      filePath = input?.tool_input?.file_path || '';
      break;
    case 'Glob': {
      const pattern = input?.tool_input?.pattern || '';
      const dir = input?.tool_input?.path || '';
      filePath = dir ? `${dir}/${pattern}` : pattern;
      break;
    }
    case 'Grep': {
      filePath = input?.tool_input?.path || '';
      const searchPattern = input?.tool_input?.pattern || '';
      for (const re of GREP_SECRET_EXTRACTION) {
        if (re.test(searchPattern)) {
          deny('Searching for secret values / token shapes blocked', searchPattern);
        }
      }
      break;
    }
  }

  if (!filePath) process.exit(0);

  // Check the path as given AND its symlink-resolved form.
  const resolved = safeRealpath(filePath);
  const candidates = resolved !== filePath ? [filePath, resolved] : [filePath];

  for (const p of candidates) {
    const reason = pathMatchesAnySensitive(p);
    if (reason) {
      deny('Access to sensitive file/path blocked: ' + reason, p);
    }
    if (tool === 'Glob' && SENSITIVE_GLOB.test(p)) {
      deny('Glob pattern targeting sensitive files blocked', p);
    }
  }

  audit('fallthrough', '', filePath);
  process.exit(0);
});
