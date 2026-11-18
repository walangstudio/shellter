#!/usr/bin/env node
// PreToolUse hook for Read/Edit/Write/Glob/Grep. Blocks access to sensitive
// paths (resolves symlinks first) and detects prompt-injection / polyglot /
// invisible-character attacks in written content.
// CLAUDE_HOOK_LOG=/path or CLAUDE_HOOK_DEBUG=1 to record decisions.

'use strict';

if (!module.parent && require('./watchdog.js').parent(__filename, 'check-sensitive-files')) return;
const fs = require('fs');
const path = require('path');
const watchdog = require('./watchdog.js');
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
  watchdog.finish(output);
}

// A dual-use content signal (legitimate in docs/CI, suspicious in a config an agent fabricates)
// surfaces for approval instead of hard-denying -- a wrong deny cannot be overridden in-session.
// In bypassPermissions and auto mode the user has opted out of prompts, and a hook `ask` there
// is either a prompt they did not want or (auto) an unconditional allow that skips the classifier.
// Pass through instead: bypass runs it, auto lets its classifier judge. Denies are unaffected.
let quietAsk = false;
function ask(reason, snippet) {
  if (quietAsk) { audit('fallthrough', 'ask suppressed (bypass/auto mode): ' + reason, snippet); process.exit(0); }
  audit('ask', reason, snippet);
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'ask',
      permissionDecisionReason: reason + ' -- approve only if you intended it',
    },
  });
  watchdog.finish(output);
}

// Resolve symlinks for the deepest existing ancestor and re-append the
// missing tail. Avoids `ln -s ~/.env /tmp/x; Read /tmp/x` bypass.
function safeRealpath(p) {
  // A non-string path (a host passing file_path as a number/array) would throw in
  // path.resolve; a crash exits nonzero and Claude Code then runs the tool UNPROTECTED, so
  // fail safe to '' (which matches nothing) instead.
  if (typeof p !== 'string' || !p) return '';
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

// One spelling for every path rule: `\` -> `/`, no NTFS stream suffix (`x::$DATA`,
// `x:stream`), no trailing dots/spaces on a segment (Windows drops them; `.`/`..` stay).
function canon(p) {
  return p.replace(/\\/g, '/')
    .replace(/^((?:[A-Za-z]:)?[^:]*[^\/:]):[^\/:]*(?::\$\w+)?$/, (m, name) => name)
    .replace(/([^\/.\s])[. ]+(?=\/|$)/g, (m, c) => c);
}
// The path as given, its symlink/junction-resolved form, and both canonical spellings.
function pathForms(p) {
  if (typeof p !== 'string' || !p) return [];
  const r = safeRealpath(p);
  return [...new Set([p, canon(p), r, r && canon(r)])].filter(Boolean);
}

// Strip invisible/steganographic characters. Tag chars and bidi overrides have no legitimate
// use anywhere (`danger`); zero-widths are counted separately by suspiciousZW.
function stripInvisibles(s) {
  if (typeof s !== 'string') return { clean: s, danger: 0 };
  const tagCount = (s.match(/[\u{E0000}-\u{E007F}]/gu) || []).length;
  const bidiCount = (s.match(/[‪-‮⁦-⁩]/g) || []).length;
  const clean = s
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/[‪-‮⁦-⁩]/g, '')
    .replace(/[​-‍⁠﻿]/g, '');
  return { clean, danger: tagCount + bidiCount };
}

// Zero-width characters that are not part of normal text: a ZWJ joins emoji (both neighbours
// emoji-ish) and a BOM at offset 0 is an encoding mark; anything else counts.
const emojiish = (c) => c >= 0x1f000 || (c >= 0x2190 && c <= 0x2bff) || c === 0xfe0f;
function suspiciousZW(s) {
  if (!/[​-‍⁠﻿]/.test(s)) return 0;
  const cp = Array.from(s, (ch) => ch.codePointAt(0));
  let n = 0;
  for (let i = 0; i < cp.length; i++) {
    const c = cp[i];
    if (!((c >= 0x200b && c <= 0x200d) || c === 0x2060 || c === 0xfeff)) continue;
    if (c === 0xfeff && i === 0) continue;
    if (c === 0x200d && i > 0 && emojiish(cp[i - 1]) && emojiish(cp[i + 1] || 0)) continue;
    n++;
  }
  return n;
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
// A bare eval/exec of a decode denies. A METHOD `.exec(` over a decode asks: `re.exec(atob(x))`
// (a regex match) and `cp.exec(atob(x))` (a shell) look the same here.
const DECODE_CALL = '\\s*\\(\\s*(?:base64\\b[\\w.]*|atob|Buffer\\.from)\\s*\\(';
const ENCODED_EVAL_PATTERN = new RegExp('(?<![.\\w$])(?:eval|exec)' + DECODE_CALL, 'i');
const ENCODED_METHOD_EXEC = new RegExp('\\.\\s*(?:eval|exec)' + DECODE_CALL, 'i');

// Fake tool-call injection (attacker-controlled file pretending to be an
// assistant message).
const TOOL_CALL_INJECTION_PATTERN = /<\/?(function_calls|invoke|tool_use|tool_call)\b|<invoke\s+name=/i;

// Markdown-rendered XSS-style URLs.
// Only where it renders (markdown / HTML, or a file an agent ingests); a sanitizer test in
// `.js` legitimately carries the string.
const MARKDOWN_DANGEROUS_URL = /\]\(\s*(?:javascript:|vbscript:|data:text\/html)/i;
const RENDERED_DOC_EXT = /\.(?:md|mdx|markdown|html?)$/i;

// ANSI escape sequences in source files (terminal-display obfuscation).
const ANSI_ESCAPE_PATTERN = /\x1b\[[\d;]*[A-Za-z]/;
const ANSI_TARGET_EXTENSIONS = /\.(js|ts|jsx|tsx|py|rs|go|md|txt|json|yaml|yml|html|c|cpp|h|hpp|java|rb|sh|bash)$/i;

// Polyglot: shell command substitution in data files (NOT markdown).
const POLYGLOT_EXTENSIONS = /\.(json|yaml|yml|xml|csv|txt|toml|ini|cfg|conf)(\.(bak|old|backup|orig|tmp|swp|save))?$/i;
// A remote fetch inside a command substitution (`$(curl …)`, `` `wget …` ``) in a data/config file
// is the polyglot / supply-chain shape. It used to also match any interpreter name (bash/sh/python/
// perl/ruby) and HARD-deny, which blocked a .txt note mentioning `python -c` in inline-code backticks
// and a CI .yml `run:` step using `$(python …)`. Interpreter mentions are routine; running them is
// gated by the Bash hook anyway. Only the fetch shape is flagged, and it ASKS (CI installers do this).
const POLYGLOT_PATTERN = /(\$\(|`)\s*(?:env\s+)?(?:[\w.~\\/-]{0,128}[\\/])?(curl|wget|nc|iwr|Invoke-WebRequest|Invoke-RestMethod)\b/i;

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
const SENSITIVE_FILES = /(^|\/)(\.git-credentials|_netrc|proc\/[^\/]+\/environ|\.npmrc|\.yarnrc|\.pnpmrc|\.pypirc|\.cargo\/credentials(\.toml)?|\.gem\/credentials|\.docker\/config\.json|\.config\/git\/credentials|\.ssh\/config|\.aws\/sso\/cache)(\/|$)/i;
const ENV_FILE = /(^|\/)\.env(?:rc|[_-][A-Za-z0-9_-]+)?(?!\.(?:example|sample|template|dist|defaults?)(?:$|\.))(\.[a-zA-Z0-9_-]+)*(\.(bak|old|backup|orig|save))?$/i;
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
const BROWSER_DATA_PATTERN = /(Chrome|Chromium|Firefox|firefox|Edge|Safari|google-chrome|mozilla)[^\/]*\/.*\/(Cookies|Cookies-journal|Login Data|Web Data)$/i;
// shellter's own trust store and installed hooks: a write there is the agent granting itself
// trust or switching shellter off. The dev repo's `hooks/` (no `.claude` segment) is not matched,
// and a fixture that merely shares the store's file name is not the store (see isTrustStore).
const SHELLTER_SELF = /(^|\/)\.claude\/shellter-trust\.json$|\/\.claude\/(?:hooks|plugins)\/.*(?:check-bash|check-sensitive-files|scan-content|watchdog|shellter-(?:trust|scan))\.js$/i;
// The plugin's installed copy: a write anywhere in it can switch shellter off.
const SHELLTER_PLUGIN_CACHE = /(^|\/)\.claude\/plugins\/(?:cache|marketplaces)\/(?:[^\/]+\/)*shellter\//i;
// Allow rules and hooks live here. The user edits it too, so ask, never deny.
const CLAUDE_SETTINGS = /(^|\/)\.claude\/settings(?:\.local)?\.json$/i;
// The user's own shell history and Claude config: plausibly holds a pasted token, but
// reading it is also routine. Ask, never deny.
const PERSONAL_HISTORY = /(^|\/)(?:\.(?:bash|zsh)_history|\.claude\.json)$/i;
// macOS Keychain databases.
const MACOS_KEYCHAIN = /(^|\/)(Library\/Keychains\/|login\.keychain(-db)?$|System\.keychain$)/i;
// Windows credential / hive files. The bare hive names (SAM/SYSTEM/SECURITY) require a
// registry `config\` path context so a repo file named `SECURITY` or a module `SYSTEM`
// is not flagged; NTUSER.DAT and the AppData credential stores stay matched anywhere.
const WINDOWS_SECRETS = /(^|[\/\\])NTUSER\.DAT$|[\/\\]config[\/\\](SAM|SYSTEM|SECURITY|SOFTWARE|DEFAULT)$|AppData[\/\\]Roaming[\/\\]Microsoft[\/\\](Credentials|Vault|Protect)([\/\\]|$)/i;
// Unix credential stores: password hashes and the sudoers policy. Anchored to `/etc/`
// so a repo file named `shadow` is not flagged; `master.passwd` is the BSD/macOS shadow
// file. `/etc/passwd` is intentionally absent -- world-readable, holds no secret.
// Trailing `-?` catches the backup shadow files (`/etc/shadow-`, `/etc/gshadow-`) that
// hold the same password hashes; `/etc/shadowfoo` still does not match.
const UNIX_SHADOW = /(^|\/)etc\/(g?shadow|sudoers(?:\.d)?|master\.passwd)-?(\/|$)/i;

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
// Regex tokens between the keyword and the separator (`password\s*=\S`, `token.*:`) count as gap.
const GREP_KEYWORD_EXTRACTION = /(password|secret|api.?key|token|credential|private.?key)(?:\s|\\[sSwW][*+?]?|\.[*+?]|\[\^?[^\]]{0,16}\][*+?]?){0,6}[:=](?:\s|\\[sS][*+?]?){0,4}[^${\s]/i;
// A token SHAPE written as a regex (`AKIA[0-9A-Z]{16}`, `ghp_[A-Za-z0-9]{36}`, `BEGIN.*PRIVATE KEY`):
// case-sensitive and followed by regex syntax, so `privateKey` or `beginSection` is not one. This
// repo's own source is full of those strings, so only a broad search path denies.
// A token prefix followed by regex syntax (a class, `.`, `\w`, a group): `privateKey` or `token: string` is not one.
const GREP_TOKEN_SHAPE = /(?:AKIA|gh(?:[pousr]|\[[pousr]+\])_|xox[a-z]?-?|eyJ)(?:\[|\.|\\[wWdDsS]|\()|BEGIN[\s\S]{0,24}PRIVATE KEY/i;

// A broad search path is a place to harvest from, not a project: a filesystem or drive root, a
// home root (any user's) or an ancestor of it, a dot-directory directly under a home root, or
// system config. A project below a home directory is not broad.
const HOME_ROOT = '(?:/(?:home|users)/[^/]+|[a-z]:/users/[^/]+|/root)';
const BROAD_RE = new RegExp('^(?:/?|[a-z]:/?|/(?:home|users|var|usr|opt|srv|mnt|mount|private)/?|[a-z]:/users/?|' +
  HOME_ROOT + '(?:/\\.[^/]+)?/?|/(?:private/)?etc(?:/.*)?)$', 'i');
function isBroadSearchPath(p) {
  if (typeof p !== 'string' || !p) return false;
  let home = '';
  try { home = canon(require('os').homedir()).replace(/\/+$/, '').toLowerCase(); } catch { /* no home */ }
  const forms = pathForms(p.replace(/^~(?=[\\/]|$)/, home || '~'));
  return forms.some((f) => {
    const c = canon(f).replace(/\/{2,}/g, '/').replace(/\/(?:\.\/)+/g, '/').replace(/^\/\/\?\//, '').toLowerCase();
    if (BROAD_RE.test(c)) return true;
    const t = c.replace(/\/+$/, '');
    return !!home && ((home + '/').startsWith(t + '/') || new RegExp('^' + home.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '/\\.[^/]+$').test(t));
  });
}

// A glob names a secret only through a literal secret stem: after brace expansion and `[x]` -> `x`,
// the last component with its glob runs removed still holds a secret name, or a directory component
// is literally `.ssh`/`.aws`/`.gnupg`. Guessing from wildcards false-denied `**/*credential*`.
const SECRET_STEM = /\.env(?!\.(?:example|sample|template|dist|defaults?)\b)|id_rsa|id_ed25519|id_ecdsa|\.netrc|\.npmrc|\.pgpass|\.git-credentials|\.pem$|\.key$/i;
const SECRET_NAMES = ['.env', 'id_rsa', 'id_ed25519', 'id_ecdsa', '.netrc', '.npmrc', '.pgpass', '.git-credentials'];
function globNamesSecret(g) {
  if (typeof g !== 'string' || !/[*?[{]/.test(g)) return false;
  return [g, ...scan.expandBraces(g)].some((f) => {
    const parts = f.replace(/\\/g, '/').replace(/\[([^\]\\])\]/g, '$1').split('/');
    if (parts.slice(0, -1).some((c) => /^\.(?:ssh|aws|gnupg)$/i.test(c))) return true;
    const last = parts[parts.length - 1];
    // Without `*`, a `?` or a class stands for one character: `.e?v`, `id_rs?` name the secret itself.
    if (!last.includes('*')) { const rx = scan.globComponentRe(last); if (rx && SECRET_NAMES.some((s) => rx.test(s))) return true; }
    // No `[` after the last `]` can close: split there so the class scan stays linear.
    const k = last.lastIndexOf(']') + 1;
    return SECRET_STEM.test(last.slice(0, k).replace(/\[[^\]]*\]|[*?]+/g, '') + last.slice(k).replace(/[*?]+/g, ''));
  });
}

// The real trust store, resolved: a fixture that shares its file name is not it.
function isTrustStore(p) {
  let store = '';
  try { store = canon(safeRealpath(require('./shellter-trust.js').trustStorePath())).toLowerCase(); } catch { return false; }
  return !!store && canon(p).toLowerCase() === store;
}

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
  if (UNIX_SHADOW.test(p)) return 'Unix password-hash / sudoers file';
  return null;
}

const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit']);
let pendingAsk = null;   // a dual-use content signal, emitted only after every deny check
let writtenText = '';    // the new text of a write tool, for target rules that depend on it
watchdog.input((data) => {
  let input;
  try {
    input = JSON.parse(data.replace(/^\uFEFF/, ''));
  } catch {
    process.exit(0);
  }
  quietAsk = typeof input?.permission_mode === 'string' && /^(?:bypassPermissions|auto)$/.test(input.permission_mode);

  const tool = input?.tool_name || '';

  // ---- content checks for Write / Edit / MultiEdit / NotebookEdit ----
  if (WRITE_TOOLS.has(tool)) {
    // `x || ''` keeps a non-string truthy value (a number), which then throws in the string
    // scanners -> nonzero exit -> Claude Code runs the tool UNPROTECTED. Only keep strings.
    const str = (v) => (typeof v === 'string' ? v : '');
    let content = '';
    if (tool === 'Write') content = str(input?.tool_input?.content);
    else if (tool === 'Edit') content = str(input?.tool_input?.new_string);
    else if (tool === 'NotebookEdit') content = str(input?.tool_input?.new_source);
    else if (tool === 'MultiEdit') {
      const edits = input?.tool_input?.edits;
      content = Array.isArray(edits) ? edits.map(e => str(e && e.new_string)).join('\n') : '';
    }
    writtenText = content;
    const filePath = tool === 'NotebookEdit'
      ? (input?.tool_input?.notebook_path || input?.tool_input?.file_path || '')
      : (input?.tool_input?.file_path || '');

    // NOTE: the full content is scanned (no size cap). Truncating before the scan
    // would let a payload past the cutoff land on disk unscanned; the inline regex
    // checks are linear and decodeOneLayer is already token-bounded, so a large
    // write costs some CPU but never creates a blind spot.

    if (content) {
      const { clean, danger } = stripInvisibles(content);
      const flat = clean.replace(/\n/g, ' ');

      const isBinary = /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|webp|ico|pdf|zip|gz|bz2|xz|7z|tar|wasm|exe|dll|so|dylib|bin|node)$/i.test(filePath);
      if (!isBinary) {
        if (danger > 0) {
          deny('Tag-character / bidi-override Unicode detected -- steganographic prompt injection', filePath);
        }
        if (SOURCE_LIKE_EXT.test(filePath) && suspiciousZW(content) > 0) {
          deny('Zero-width characters in source file -- possible steganographic injection', filePath);
        }
      }

      const instructionSurface = pathForms(filePath).some(scan.isAgentInstructionFile);

      // A fake tool-call tag is legitimate content when documenting an agent framework,
      // so it hard-denies only when written to a file an agent auto-ingests.
      if (TOOL_CALL_INJECTION_PATTERN.test(flat) && instructionSurface) {
        deny('Fake tool-call tag written to an agent-instruction file blocked', filePath);
      }

      if (ENCODED_EVAL_PATTERN.test(flat)) {
        deny('Encoded eval/exec pattern in file content blocked', filePath);
      }
      if (ENCODED_METHOD_EXEC.test(flat)) {
        pendingAsk = pendingAsk || { reason: 'exec/eval method call on decoded data in file content', snippet: filePath };
      }

      if ((instructionSurface || RENDERED_DOC_EXT.test(filePath)) && MARKDOWN_DANGEROUS_URL.test(flat)) {
        deny('Markdown javascript:/data:/vbscript: URL blocked', filePath);
      }

      if (ANSI_TARGET_EXTENSIONS.test(filePath) && ANSI_ESCAPE_PATTERN.test(content)) {
        if (instructionSurface) deny('ANSI escape sequence in an agent-instruction file blocked', filePath);
        pendingAsk = pendingAsk || { reason: 'ANSI escape sequence in source file', snippet: filePath };
      }

      // Deferred: an ask must never pre-empt a deny, so this is emitted only after every deny
      // check below (injection scan, sensitive-path match) has had its say.
      if (POLYGLOT_EXTENSIONS.test(filePath) && POLYGLOT_PATTERN.test(flat)) {
        pendingAsk = pendingAsk || { reason: 'Remote fetch inside a command substitution in a data/config file', snippet: filePath };
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
        if (instructionSurface && inj.some(f => f.signal === 'decode-budget-exhausted')) {
          pendingAsk = pendingAsk || { reason: 'Too many encoded tokens to inspect in an agent-instruction file', snippet: filePath };
        }
        if (instructionSurface) {
          const med = inj.find(f => f.severity === 'medium' && f.category === 'injection');
          if (med) {
            deny('Prompt injection in agent-instruction file: ' + med.signal + (med.line ? ' (line ' + med.line + ')' : ''), filePath);
          }
          const q = inj.find(f => f.signal === 'instruction-override-quoted');
          if (q) pendingAsk = pendingAsk || { reason: 'Quoted instruction-override phrase in an agent-instruction file' + (q.line ? ' (line ' + q.line + ')' : ''), snippet: filePath };
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
      if (isBroadSearchPath(filePath) && GREP_KEYWORD_EXTRACTION.test(searchPattern)) {
        deny('Searching for plaintext credentials across a home/system path blocked', searchPattern);
      }
      if (isBroadSearchPath(filePath) && GREP_TOKEN_SHAPE.test(searchPattern)) {
        deny('Searching for secret token shapes across a home/system path blocked', searchPattern);
      }
      // The file filter selects what gets read: `glob: "**/.env*"` reads every .env.
      const gl = input?.tool_input?.glob;
      if (typeof gl === 'string' && gl) {
        for (const p of pathForms(filePath ? filePath + '/' + gl : gl)) {
          if (pathMatchesAnySensitive(p) || SENSITIVE_GLOB.test(p) || globNamesSecret(p)) {
            deny('Grep over sensitive files blocked', p);
          }
        }
      }
      break;
    }
  }

  if (!filePath) { if (pendingAsk) ask(pendingAsk.reason, pendingAsk.snippet); process.exit(0); }

  for (const p of pathForms(filePath)) {
    const reason = pathMatchesAnySensitive(p);
    if (reason) {
      deny('Access to sensitive file/path blocked: ' + reason, p);
    }
    if (WRITE_TOOLS.has(tool) && (SHELLTER_SELF.test(p) || isTrustStore(p) || SHELLTER_PLUGIN_CACHE.test(p) ||
        (/(^|\/)\.claude\/hooks\/package\.json$/i.test(p) && /"type"\s*:\s*"module"/.test(writtenText)))) {
      deny('Writing shellter\'s own trust store or hooks blocked', p);
    }
    if (WRITE_TOOLS.has(tool) && CLAUDE_SETTINGS.test(p)) {
      pendingAsk = pendingAsk || { reason: 'Editing Claude Code settings (allow rules, hooks)', snippet: p };
    }
    if (PERSONAL_HISTORY.test(p)) {
      pendingAsk = pendingAsk || { reason: 'Shell history / Claude config may hold tokens', snippet: p };
    }
    if (tool === 'Glob' && (SENSITIVE_GLOB.test(p) || globNamesSecret(p))) {
      deny('Glob pattern targeting sensitive files blocked', p);
    }
  }

  if (pendingAsk) ask(pendingAsk.reason, pendingAsk.snippet);
  audit('fallthrough', '', filePath);
  process.exit(0);
});
