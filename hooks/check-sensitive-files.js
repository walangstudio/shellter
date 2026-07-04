#!/usr/bin/env node
// PreToolUse hook for Read/Edit/Write/Glob/Grep. Blocks access to sensitive
// paths (resolves symlinks first) and detects prompt-injection / polyglot /
// invisible-character attacks in written content.
// CLAUDE_HOOK_LOG=/path or CLAUDE_HOOK_DEBUG=1 to record decisions.

'use strict';

const fs = require('fs');
const path = require('path');
const scan = require('./scan-content.js');

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

const BYPASS_NOTICE =
  ' | shellter blocked this to protect the user. Do NOT bypass, re-encode, copy, rename, or work ' +
  'around it; stop and tell the user what was blocked and why so they can decide.';

function deny(reason, snippet) {
  audit('deny', reason, snippet);
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason + BYPASS_NOTICE,
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

// `scan.isAgentInstructionFile(path)` (shared, defined in scan-content.js) flags files an
// agent auto-ingests as instructions -- an injected payload written there can hijack a
// later agent turn, so a Class-B injection signal is hard-denied ONLY for those targets.
// Anywhere else those signals are advisory: a security write-up, a chatbot system-prompt
// string, or an example conversation is legitimate content, so shellter does not block it.
//
// Instruction-override / role-hijack PHRASE matching lives in scan-content.js
// (`scanInjection`) -- severity-tiered (Class A always-deny vs Class B destination-gated)
// and exfil-aware. The older flat INJECTION_PATTERNS + HTML-comment list was retired
// here: it hard-denied any file containing "you are now a", "act as if", "<system>",
// "[SYSTEM]", a `User:`/`Assistant:` transcript, or "<!-- ... http ... -->", which blocks
// ordinary docs, tests, and AI-app source. The disciplined scanner below replaces it.
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
// `.env` excludes the placeholder templates (.env.example/.sample/.template/.dist/
// .defaults) -- they hold no real secrets and copying/reading them is routine.
// .env.local / .env.production etc. still match (those carry real values).
// `.crt` dropped: an X.509 certificate is public by definition, so reading one is not a
// secret access. Private-key extensions (.pem/.key/.p12/...) stay.
const SENSITIVE_EXTENSIONS = /\.(?:env(?!\.(?:example|sample|template|dist|defaults?)\b)|pem|key|p12|pfx|ppk|jks|keystore|secret|credentials|pgpass|netrc|npmrc)(\.(bak|old|backup|orig|swp|save))?(\.\d+)?\b/i;
const SENSITIVE_DIRS = /(^|\/)(\.ssh|\.gnupg|\.aws|\.gcloud|\.azure|\.kube|\.docker\/config|\.config\/(gh|hub|gcloud)|id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)(\/|$)/i;
// .gitconfig deliberately excluded: tokens normally live in .git-credentials.
const SENSITIVE_FILES = /(^|\/)(\.git-credentials|\.npmrc|\.yarnrc|\.pnpmrc|\.pypirc|\.cargo\/credentials(\.toml)?|\.gem\/credentials|\.docker\/config\.json|\.config\/git\/credentials|\.ssh\/config|\.aws\/sso\/cache)(\/|$)/i;
const ENV_FILE = /(^|\/)\.env(?!\.(?:example|sample|template|dist|defaults?)(?:$|\.))(\.[a-zA-Z0-9_-]+)*(\.(bak|old|backup|orig|save))?$/i;
const SECRETS_DIR = /(^|\/)(secrets?|credentials?|private[_-]?keys?)(\/|$)/i;
// A source-code file inside a dir named credentials/secrets is code, not a secret
// (`src/credentials/oauth.ts`), so it is exempt from the SECRETS_DIR match. Data files
// (.json/.yaml/.env/...) inside such a dir stay flagged.
// Source-code extensions ONLY -- deliberately excludes doc/text/data extensions (.md/.txt/
// .rst/.json/.yaml), since a `secrets/master.txt` or `credentials/prod.json` is plausibly
// real secret material, not code.
const CODE_FILE_EXT = /\.(?:ts|tsx|js|jsx|mjs|cjs|py|go|rs|java|rb|php|c|cc|cpp|h|hpp|kt|kts|swift|scala|clj|ex|exs|css|scss|less|vue|svelte|html)$/i;
const SENSITIVE_GLOB = /\*\.(env|pem|key|crt|secret)/i;

// Wallet / crypto / browser cookie files.
const WALLET_PATTERN = /\b(wallet\.dat|keystore\.json|UTC--\d{4}-\d{2}-\d{2}T)\b|(^|\/)\.electrum\/wallets\/|(^|\/)\.bitcoin\/wallet\.dat$/i;
const BROWSER_DATA_PATTERN = /(Chrome|Chromium|Firefox|firefox|Edge|Safari|google-chrome|mozilla)[^\/]*\/.*\/(Cookies|Cookies-journal|Login Data|Web Data)$/;
// macOS Keychain databases.
const MACOS_KEYCHAIN = /(^|\/)(Library\/Keychains\/|login\.keychain(-db)?$|System\.keychain$)/i;
// Windows credential / hive files. The bare hive names (SAM/SYSTEM/SECURITY) require a
// registry `config\` path context so a repo file named `SECURITY` or a module `SYSTEM`
// is not flagged; NTUSER.DAT and the AppData credential stores stay matched anywhere.
const WINDOWS_SECRETS = /(^|[\/\\])NTUSER\.DAT$|[\/\\]config[\/\\](SAM|SYSTEM|SECURITY|SOFTWARE|DEFAULT)$|AppData[\/\\]Roaming[\/\\]Microsoft[\/\\](Credentials|Vault|Protect)([\/\\]|$)/i;

// Concrete secret-token SHAPES -- blocked on any path (grepping for a live key value is
// harvesting regardless of where you look).
const GREP_SECRET_EXTRACTION = [
  /AKIA[0-9A-Z]{16}/,
  /gh[pousr]_[A-Za-z0-9_]{36,}/,
  /xox[bpoa]-[\w-]+/,
  /eyJ[A-Za-z0-9_-]{10,}\.eyJ/,
  /[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}/,
];
// A `keyword = value` extraction (searching for a plaintext credential assignment). This is
// a routine self-audit inside your own repo, so it is denied ONLY when the search path is a
// broad off-project location (a home/system root) -- i.e. mass credential harvesting.
const GREP_KEYWORD_EXTRACTION = /(password|secret|api.?key|token|credential|private.?key)\s*[:=]\s*[^${\s]/i;
const BROAD_SEARCH_PATH = /^(?:~|\/(?:home|Users|etc|root|var|opt|usr|private|srv|mnt|mount)\b|\/$|[A-Za-z]:[\\\/]Users\b)/i;

function pathMatchesAnySensitive(p) {
  if (!p) return null;
  if (SENSITIVE_EXTENSIONS.test(p)) return 'sensitive extension';
  if (SENSITIVE_DIRS.test(p)) return 'sensitive directory/file';
  if (SENSITIVE_FILES.test(p)) return 'sensitive credential file';
  if (ENV_FILE.test(p)) return '.env file';
  if (SECRETS_DIR.test(p) && !CODE_FILE_EXT.test(p)) return 'secrets/credentials directory';
  if (WALLET_PATTERN.test(p)) return 'wallet / crypto key file';
  if (BROWSER_DATA_PATTERN.test(p)) return 'browser cookie/login database';
  if (MACOS_KEYCHAIN.test(p)) return 'macOS Keychain database';
  if (WINDOWS_SECRETS.test(p)) return 'Windows credential / registry hive';
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

  // ---- content checks for Write / Edit / MultiEdit / NotebookEdit ----
  if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit' || tool === 'NotebookEdit') {
    let content = '';
    if (tool === 'Write') content = input?.tool_input?.content || '';
    else if (tool === 'Edit') content = input?.tool_input?.new_string || '';
    else if (tool === 'NotebookEdit') content = input?.tool_input?.new_source || '';
    else if (tool === 'MultiEdit') {
      const edits = input?.tool_input?.edits;
      content = Array.isArray(edits) ? edits.map(e => (e && e.new_string) || '').join('\n') : '';
    }
    const filePath = tool === 'NotebookEdit'
      ? (input?.tool_input?.notebook_path || input?.tool_input?.file_path || '')
      : (input?.tool_input?.file_path || '');

    // NOTE: the full content is scanned (no size cap). Truncating before the scan
    // would let a payload past the cutoff land on disk unscanned; the inline regex
    // checks are linear and decodeOneLayer is already token-bounded, so a large
    // write costs some CPU but never creates a blind spot.

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

      const instructionSurface = scan.isAgentInstructionFile(filePath);

      // A fake tool-call tag is legitimate content when documenting an agent framework,
      // so it hard-denies only when written to a file an agent auto-ingests.
      if (TOOL_CALL_INJECTION_PATTERN.test(flat) && instructionSurface) {
        deny('Fake tool-call tag written to an agent-instruction file blocked', filePath);
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

      // Disciplined injection scan (variation-selector smuggling, homoglyph, role
      // markers, Policy-Puppetry, MCP tool-poisoning, override+exfil, decode-one-layer).
      // Class A (HIGH) always denies. Class B (MEDIUM injection: bare override phrase,
      // role marker, fake transcript, HTML-comment action) denies only on an
      // agent-instruction surface -- elsewhere it is legitimate authored content.
      if (!isBinary) {
        const inj = scan.scanInjection(content, { decode: true });
        const hi = inj.find(f => f.severity === 'high');
        if (hi) {
          deny('Prompt injection detected: ' + hi.signal + (hi.line ? ' (line ' + hi.line + ')' : ''), filePath);
        }
        if (instructionSurface) {
          const med = inj.find(f => f.severity === 'medium' && f.category === 'injection');
          if (med) {
            deny('Prompt injection in agent-instruction file: ' + med.signal + (med.line ? ' (line ' + med.line + ')' : ''), filePath);
          }
        }
      }
    }
  }

  // ---- extract the path to check ----
  let filePath = '';

  switch (tool) {
    case 'Read':
    case 'Edit':
    case 'Write':
    case 'MultiEdit':
      filePath = input?.tool_input?.file_path || '';
      break;
    case 'NotebookEdit':
      filePath = input?.tool_input?.notebook_path || input?.tool_input?.file_path || '';
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
      // keyword=value harvesting across a broad off-project path (a self-audit in your own
      // repo, i.e. a relative path, stays allowed).
      if (BROAD_SEARCH_PATH.test(filePath) && GREP_KEYWORD_EXTRACTION.test(searchPattern)) {
        deny('Searching for plaintext credentials across a home/system path blocked', searchPattern);
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
