'use strict';
// Shared, zero-dependency content scanner. No I/O. Cross-platform.
// Used by check-bash.js (shell-malice inside executed scripts) and
// check-sensitive-files.js (prompt-injection inside written content).
//
// Returns structured findings: { category, signal, line, snippet, severity }.
// Only `high` severity is meant to drive a deny/ask; `medium`/`low` are advisory
// (callers log them). The single biggest false-positive lever is keeping a signal
// at `medium` unless it is a high-confidence malicious shape.
//
// NOTE: invisible-char ranges and every fake-role / chat-template marker are
// written with \u escapes / escaped metacharacters on purpose -- embedding the
// literal bytes would make this file trip the injection detector on install.

const SEVERITY = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const RANK = { high: 3, medium: 2, low: 1 };

// ---- invisible / steganographic Unicode -------------------------------------

const TAG_RE = /[\u{E0000}-\u{E007F}]/gu;                    // tag block (ASCII smuggling)
const BIDI_RE = /[‪-‮⁦-⁩]/g;            // bidi overrides (Trojan Source)
const ZW_RE = /[​-‍⁠﻿]/g;               // zero-width
const VS_RE = /[︀-️]|[\u{E0100}-\u{E01EF}]/gu;    // variation selectors

// A variation selector is suspicious when it does NOT sit on an emoji-like base
// (legit use is a single VS16/skin-tone on an emoji). Smuggling appends runs of
// selectors, uses the VS17-256 supplement (E0100+), or attaches them to ASCII.
function countSuspiciousVS(s) {
  const cp = Array.from(s);
  let n = 0;
  for (let i = 0; i < cp.length; i++) {
    const c = cp[i].codePointAt(0);
    const isVS = (c >= 0xfe00 && c <= 0xfe0f) || (c >= 0xe0100 && c <= 0xe01ef);
    if (!isVS) continue;
    if (c >= 0xe0100) { n++; continue; }            // supplement: no legit text use
    const prev = i > 0 ? cp[i - 1].codePointAt(0) : 0;
    const prevIsEmojiBase =
      (prev >= 0x1f000) ||                            // emoji & pictographs
      (prev >= 0x2190 && prev <= 0x2bff) ||           // arrows / misc symbols / dingbats
      (prev >= 0xfe00 && prev <= 0xfe0f);             // already a selector (skin-tone run on emoji)
    const next = i + 1 < cp.length ? cp[i + 1].codePointAt(0) : 0;
    const nextIsVS = next >= 0xfe00 && next <= 0xfe0f;
    if (!prevIsEmojiBase || nextIsVS) n++;            // ASCII base, or a run -> bitstream
  }
  return n;
}

// Recursive strip: a single pass is insufficient because interleaved surrogates
// can re-form a tag block after the first removal (Node strings are UTF-16).
function normalizeForScan(s, maxRounds = 5) {
  const counts = { tag: 0, bidi: 0, zeroWidth: 0, variationSelector: 0 };
  if (typeof s !== 'string') return { clean: s, rounds: 0, counts };
  counts.variationSelector = countSuspiciousVS(s);
  let clean = s;
  let rounds = 0;
  for (; rounds < maxRounds; rounds++) {
    const before = clean;
    counts.tag += (clean.match(TAG_RE) || []).length;
    counts.bidi += (clean.match(BIDI_RE) || []).length;
    counts.zeroWidth += (clean.match(ZW_RE) || []).length;
    clean = clean.replace(TAG_RE, '').replace(BIDI_RE, '').replace(ZW_RE, '').replace(VS_RE, '');
    if (clean === before) break;
  }
  return { clean, rounds, counts };
}

// ---- helpers ----------------------------------------------------------------

function shannonEntropy(str) {
  if (!str) return 0;
  const freq = Object.create(null);
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  const len = str.length;
  for (const k in freq) {
    const p = freq[k] / len;
    h -= p * Math.log2(p);
  }
  return h;
}

function maskSecrets(s) {
  return s.replace(/[A-Za-z0-9+/_=-]{20,}/g, m => m.slice(0, 6) + '...[' + m.length + ']');
}

function locate(text, index) {
  if (index < 0) index = 0;
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  const start = text.lastIndexOf('\n', index - 1) + 1;
  let end = text.indexOf('\n', index);
  if (end === -1) end = text.length;
  let snippet = text.slice(start, end).trim();
  if (snippet.length > 120) snippet = snippet.slice(0, 117) + '...';
  return { line, snippet: maskSecrets(snippet) };
}

// Decode the highest-value encoded tokens once (NO recursion -- a DoS guard).
// Returns concatenated decoded text (utf8, plus utf16le when the buffer looks
// like UTF-16LE, e.g. PowerShell -EncodedCommand). Empty string when nothing
// worth decoding.
function decodeOneLayer(text, opts) {
  opts = opts || {};
  const maxTokens = opts.maxTokens || 8;
  const minLen = opts.minLen || 24;
  const maxLen = opts.maxLen || 8192;
  const minEntropy = opts.minEntropy || 3.5;
  const out = [];
  let used = 0;

  const b64 = /[A-Za-z0-9+/]{24,}={0,2}/g;
  let m;
  while ((m = b64.exec(text)) && used < maxTokens) {
    const tok = m[0];
    if (tok.length < minLen || tok.length > maxLen) continue;
    if (shannonEntropy(tok) < minEntropy) continue;
    try {
      const buf = Buffer.from(tok, 'base64');
      if (!buf.length) continue;
      const u8 = buf.toString('utf8');
      if (printableRatio(u8) > 0.8) out.push(u8);
      const nulls = countNulls(buf);
      if (nulls > buf.length / 4) {
        const u16 = buf.toString('utf16le');
        if (printableRatio(u16) > 0.8) out.push(u16);
      }
      used++;
    } catch { /* not base64 */ }
  }

  const hex = /\b(?:[0-9a-fA-F]{2}){16,}\b/g;
  while ((m = hex.exec(text)) && used < maxTokens) {
    try {
      const u8 = Buffer.from(m[0], 'hex').toString('utf8');
      if (printableRatio(u8) > 0.8) { out.push(u8); used++; }
    } catch { /* not hex */ }
  }
  return out.join('\n');
}

function printableRatio(s) {
  if (!s.length) return 0;
  let p = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 160) p++;
  }
  return p / s.length;
}

function countNulls(buf) {
  let n = 0;
  for (let i = 0; i < buf.length; i++) if (buf[i] === 0) n++;
  return n;
}

// ---- shell-malice signal pack (for executed scripts) ------------------------
// Each entry tested per line; spans are bounded so they cannot leak across a
// whole file. `\s+` (not literal spaces) keeps the pattern source from itself
// reading as a runnable command.

const INTERP = 'bash|sh|zsh|dash|ash|ksh|fish|python[23]?|perl|ruby|node|deno|bun|php|lua';

const SHELL_HIGH = [
  [new RegExp('\\b(?:curl|wget|fetch)\\b[^\\n]{0,400}\\|\\s*(?:[^\\s|]*/)?(?:' + INTERP + ')\\b', 'i'), 'download-piped-to-shell'],
  [new RegExp('\\b(?:bash|sh|zsh)\\s+<\\(\\s*(?:curl|wget)', 'i'), 'process-substitution-download-exec'],
  [/\/dev\/(?:tcp|udp)\//i, 'reverse-shell-dev-tcp'],
  [/\bbash\s+-i\b[^\n]{0,40}(?:>&|0>&1|\/dev\/(?:tcp|udp))/i, 'interactive-reverse-shell'],
  [/\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-[A-Za-z]*e\b/i, 'netcat-exec'],
  [/\bmkfifo\b[^\n]{0,80}(?:nc|ncat|\/dev\/tcp)/i, 'named-pipe-reverse-shell'],
  [/\bsocat\b[^\n]{0,80}(?:EXEC|SYSTEM|exec:|system:)/i, 'socat-exec'],
  [/\bpython[23]?\s+-c\b[^\n]{0,200}(?:socket|pty\.spawn|subprocess|os\.system|os\.popen)/i, 'python-socket-exec'],
  [/\bperl\s+-e\b[^\n]{0,200}socket/i, 'perl-socket-exec'],
  [/\bruby\s+-e\b[^\n]{0,200}TCPSocket/i, 'ruby-socket-exec'],
  [/\bphp\s+-r\b[^\n]{0,200}(?:fsockopen|proc_open|shell_exec|`)/i, 'php-exec'],
  [new RegExp('\\b(?:base64|base32)\\s+(?:--?d(?:ecode)?|-D)\\b[^\\n]{0,200}\\|\\s*(?:' + INTERP + ')\\b', 'i'), 'base64-decode-exec'],
  [new RegExp('\\bxxd\\s+-r\\b[^\\n]{0,200}\\|\\s*(?:' + INTERP + ')\\b', 'i'), 'hexdecode-exec'],
  // command assembled from variable indirection then piped to a shell: `$a$b ... | sh`
  [new RegExp('(?:\\$\\{?[A-Za-z_]\\w*\\}?){2,}[^\\n]{0,200}\\|\\s*(?:[^\\s|]*/)?(?:' + INTERP + ')\\b', 'i'), 'var-composed-piped-to-shell'],
  [/\beval\b[^\n]{0,8}(?:\$\(|`|\$\{|\bbase64\b|\batob\b)/i, 'eval-dynamic'],
  [/\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,200}\s-(?:e|ec|enc|encodedcommand)\b/i, 'powershell-encodedcommand'],
  [/\b(?:iex|invoke-expression)\b[^\n]{0,200}(?:downloadstring|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|net\.webclient)/i, 'powershell-iex-download'],
  [/\.(?:DownloadString|DownloadFile|DownloadData)\s*\(/i, 'powershell-webclient-download'],
  [/\biex\s*\(/i, 'powershell-iex'],
  [/(?:amsiInitFailed|AmsiUtils|amsiContext)/i, 'amsi-bypass'],
  [/\bcertutil\b[^\n]{0,80}-(?:urlcache|decode|decodehex)\b/i, 'lolbin-certutil'],
  [/\bbitsadmin\b[^\n]{0,80}\/transfer\b/i, 'lolbin-bitsadmin'],
  [/\bmshta\b\s+(?:https?:|javascript:|vbscript:)/i, 'lolbin-mshta'],
  [/\bregsvr32\b[^\n]{0,80}(?:\/i|scrobj)/i, 'lolbin-regsvr32'],
];

const SHELL_MED = [
  [/\$\{?IFS\b/, 'ifs-obfuscation'],
  [/\$\{!\w/, 'indirect-variable-expansion'],
  [/^\s*eval\b/i, 'eval'],
  [/\bprintf\b\s+['"]?(?:\\[0-7]{2,3}){4,}/, 'printf-octal-assembly'],
  [/(?:\b\w=[\w]{1,3};){2,}\s*\$\w\$\w/, 'char-by-char-command-assembly'],
];

const SHELL_LOW = [
  [/\b(?:curl|wget)\s+https?:\/\//i, 'network-fetch'],
  [/\bchmod\s+\+x\b/i, 'chmod-exec-bit'],
];

// ---- prompt-injection signal pack (for written content) ---------------------

const ROLE_MARKERS = [
  [/<\|im_(?:start|end)\|>|<\|(?:system|user|assistant|endoftext)\|>/i, 'chatml-role-marker'],
  [/\[\/?INST\]|<<\/?SYS>>/i, 'llama-mistral-role-marker'],
  [/\bBEGIN\s+SYSTEM\s+PROMPT\b/i, 'inline-system-prompt-header'],
  [/<\/?(?:system|instructions?)>/i, 'xml-system-tag'],
];

const POLICY_PUPPETRY = [
  [/<interaction-config\b/i, 'policy-puppetry-config'],
  [/<(?:blocked-modes|blocked-string|allowed-responses)\b/i, 'policy-puppetry-config'],
];

// Override-phrase family. Built with \s+ so the source isn't itself a clean
// override sentence.
const OVERRIDE_RE = /\b(?:ignore|disregard|forget|discard|cancel)\s+(?:all\s+|the\s+|any\s+|your\s+)?(?:previous|prior|earlier|above|current|the\s+system)\s+(?:instructions?|prompts?|rules?|commands?|guidelines?)\b|\bstop\s+following\s+(?:your\s+|the\s+)?(?:instructions?|rules?)\b|\byou\s+are\s+now\s+(?:a|an|the|in)\b|\bnew\s+(?:instructions?|system\s+prompt)\b/i;
const EXFIL_TARGET_RE = /(?:~\/?\.ssh|id_rsa|id_ed25519|\.env\b|\bcredentials?\b|mcp\.json|~\/?\.aws|\.git-credentials|private[_-]?key)/i;

const MCP_IMPORTANT_RE = /<IMPORTANT>[\s\S]{0,400}(?:do\s+not\s+(?:mention|tell|reveal)|read\s|send\s|curl|wget|execute|\.env\b|credentials?|~\/?\.)/i;
// Tempered `(?:(?!-->)[\s\S])` runs so the body can't cross a `-->`: the keyword must
// live inside ONE comment. Stops a decorative divider from pairing with a keyword in
// unrelated content (or a separate comment) up to 400 chars away, while every real
// single-comment payload still fires. Bounded {0,400} both sides -> no runaway backtrack.
const HTML_COMMENT_ACTION_RE = /<!--(?:(?!-->)[\s\S]){0,400}(?:curl|wget|base64|exec|eval|\.env\b|id_rsa|credentials?|token|webhook|http)(?:(?!-->)[\s\S]){0,400}-->/i;

// Confusable Cyrillic/Greek letters that spoof ASCII Latin, mapped to the letter they
// imitate. Single source of truth: CONFUSABLE (for the mixed-script detector) is
// derived from the keys, so the set and the fold map cannot drift apart.
const CONFUSABLE_FOLD = {
  'А':'A','В':'B','Е':'E','К':'K','М':'M','Н':'H','О':'O','Р':'P','С':'C','Т':'T','Х':'X',
  'а':'a','е':'e','і':'i','о':'o','р':'p','с':'c','у':'y','х':'x',
  'Α':'A','Β':'B','Ε':'E','Η':'H','Ι':'I','Κ':'K','Μ':'M','Ν':'N','Ο':'O','Ρ':'P','Τ':'T','Υ':'Y','Χ':'X',
  'ο':'o','α':'a',
};
const CONFUSABLE = Object.keys(CONFUSABLE_FOLD).join('');
const HOMOGLYPH_TOKEN_RE = new RegExp('\\b(?=[A-Za-z]*[' + CONFUSABLE + '])(?=[' + CONFUSABLE + ']*[A-Za-z])[A-Za-z' + CONFUSABLE + ']{3,}\\b', 'u');
// Fold confusables to the ASCII letters they imitate, so the semantic keyword matchers
// (override/role/MCP) catch a phrase spoofed with lookalike letters (a Cyrillic letter
// standing in for the Latin one). 1:1 length-preserving (each confusable -> one ASCII
// char), so match offsets stay valid; identity on plain ASCII, so normal content is
// unaffected. Runs on every layer including the decoded one, with no content-derived
// gate, so it recovers spoofed-payload detection on encoded layers without the
// homoglyph matcher's garbage-decode false positives.
function foldConfusables(s) {
  let out = '';
  for (const ch of s) out += CONFUSABLE_FOLD[ch] || ch;
  return out;
}
const ROLE_LINE_RE = /^[ \t>*-]*\b(System|Human|Assistant|User|AI)\s*:/gim;

// ---- scanners ---------------------------------------------------------------

function pushFinding(findings, text, index, category, signal, severity) {
  const { line, snippet } = locate(text, index < 0 ? 0 : index);
  findings.push({ category, signal, line, snippet, severity });
}

function runShellPack(findings, text, category) {
  // Join backslash-newline continuations into logical lines so a token split
  // across physical lines (`cur\<nl>l ... | sh`) can't hide from the per-line
  // pack. `offset` keeps pointing at the logical line's first physical line.
  const phys = text.split('\n');
  const logical = [];
  let offset = 0, buf = '', bufOffset = 0, open = false;
  for (let i = 0; i < phys.length; i++) {
    const ln = phys[i];
    if (!open) { bufOffset = offset; open = true; }
    if (ln.endsWith('\\')) {
      buf += ln.slice(0, -1);
    } else {
      buf += ln;
      logical.push([buf, bufOffset]);
      buf = ''; open = false;
    }
    offset += ln.length + 1;
  }
  if (open) logical.push([buf, bufOffset]);

  for (const [line, off] of logical) {
    const norm = normalizeForScan(line).clean;
    for (const variant of line === norm ? [line] : [line, norm]) {
      for (const [re, sig] of SHELL_HIGH) if (re.test(variant)) pushFinding(findings, text, off, category, sig, SEVERITY.HIGH);
      for (const [re, sig] of SHELL_MED) if (re.test(variant)) pushFinding(findings, text, off, category, sig, SEVERITY.MEDIUM);
      for (const [re, sig] of SHELL_LOW) if (re.test(variant)) pushFinding(findings, text, off, category, sig, SEVERITY.LOW);
    }
  }
}

function scanShell(text, opts) {
  opts = opts || {};
  if (typeof text !== 'string' || !text) return [];
  const findings = [];
  runShellPack(findings, text, 'shell');
  if (opts.decode !== false) {
    const decoded = decodeOneLayer(text);
    if (decoded) {
      const sub = [];
      runShellPack(sub, decoded, 'shell');
      for (const f of sub) findings.push({ ...f, signal: f.signal + ':decoded', line: 0, snippet: maskSecrets(f.snippet) });
    }
  }
  return findings;
}

function scanInjectionText(findings, text, decodedLayer) {
  const { counts, clean } = normalizeForScan(text);
  // Invisible / steganographic-unicode matchers (tag, bidi-override, variation-selector,
  // zero-width) run on EVERY layer including the decoded one, as before: they catch real
  // smuggling encoded into a base64/hex layer, and these specific code points do not
  // appear in the random bytes of an ordinary decoded identifier/hash, so they don't
  // cause the false positive this release fixes (that was the homoglyph matcher below).
  if (counts.tag > 0) pushFinding(findings, text, 0, 'unicode', 'tag-char-smuggling', SEVERITY.HIGH);
  if (counts.bidi > 0) pushFinding(findings, text, 0, 'unicode', 'bidi-override', SEVERITY.HIGH);
  if (counts.variationSelector > 0) pushFinding(findings, text, 0, 'unicode', 'variation-selector-smuggling', SEVERITY.HIGH);
  if (counts.zeroWidth > 0) pushFinding(findings, text, 0, 'unicode', 'zero-width-chars', SEVERITY.MEDIUM);

  for (const [re, sig] of ROLE_MARKERS) { const m = re.exec(clean); if (m) pushFinding(findings, clean, m.index, 'injection', sig, SEVERITY.HIGH); }
  for (const [re, sig] of POLICY_PUPPETRY) { const m = re.exec(clean); if (m) pushFinding(findings, clean, m.index, 'injection', sig, SEVERITY.HIGH); }

  // Override phrases are matched on confusable-folded text so a phrase spoofed with
  // Cyrillic/Greek lookalikes is caught the same as its ASCII form, on every layer
  // including decoded -- this is what recovers a homoglyph-spoofed override hidden in a
  // base64 layer through the unconditional keyword path. Only OVERRIDE_RE is folded: it
  // matches long multi-word English phrases, so folding cannot turn real foreign-script
  // prose into a match; the short role-label matchers are left unfolded (a stray "аі:"
  // would otherwise fold to a fake "AI:" label).
  const folded = foldConfusables(clean);
  const ov = OVERRIDE_RE.exec(folded);
  if (ov) {
    const window = folded.slice(Math.max(0, ov.index - 200), ov.index + 200);
    const withExfil = EXFIL_TARGET_RE.test(window);
    pushFinding(findings, folded, ov.index, 'injection', withExfil ? 'override-with-exfil-target' : 'instruction-override', SEVERITY.HIGH);
  }

  const mi = MCP_IMPORTANT_RE.exec(clean); if (mi) pushFinding(findings, clean, mi.index, 'injection', 'mcp-tool-poisoning', SEVERITY.HIGH);
  const hc = HTML_COMMENT_ACTION_RE.exec(clean); if (hc) pushFinding(findings, clean, hc.index, 'injection', 'html-comment-action', SEVERITY.HIGH);

  // Homoglyph mixed-script is the one display-spoof matcher that fires on the random
  // bytes of a decoded ordinary identifier/hash (the reported false positive), because
  // it matches any short cross-script letter run. So it runs on LITERAL content only.
  // A spoofed *keyword* (e.g. an override phrase) is still caught on the decoded layer
  // via the folded OVERRIDE_RE above; a non-keyword homoglyph token hidden inside a
  // base64/hex layer is no longer flagged on the decoded layer (literal content still
  // is). We do not gate on a "looks like garbage" property of the decoded bytes: that
  // signal is attacker-controllable and would be an evadable suppression.
  if (!decodedLayer) {
    const hg = HOMOGLYPH_TOKEN_RE.exec(clean); if (hg) pushFinding(findings, clean, hg.index, 'injection', 'homoglyph-mixed-script', SEVERITY.HIGH);
  }

  // Fake transcript: only flag when >=2 distinct role labels appear at line start.
  // Matched on unfolded text -- folding short labels risks a Cyrillic "аі:" line folding
  // into a fake "AI:" role label.
  const seen = new Set();
  let rm; ROLE_LINE_RE.lastIndex = 0;
  let firstIdx = -1;
  while ((rm = ROLE_LINE_RE.exec(clean))) { seen.add(rm[1].toLowerCase()); if (firstIdx < 0) firstIdx = rm.index; }
  if (seen.size >= 2) pushFinding(findings, clean, firstIdx, 'injection', 'fake-transcript-role-labels', SEVERITY.HIGH);
}

function scanInjection(text, opts) {
  opts = opts || {};
  if (typeof text !== 'string' || !text) return [];
  const findings = [];
  scanInjectionText(findings, text);
  if (opts.decode !== false) {
    const decoded = decodeOneLayer(text);
    if (decoded) {
      const sub = [];
      scanInjectionText(sub, decoded, true);
      for (const f of sub) findings.push({ ...f, signal: f.signal + ':decoded', line: 0 });
    }
  }
  return findings;
}

function hasHigh(findings) { return findings.some(f => f.severity === SEVERITY.HIGH); }
function highest(findings) {
  let best = null;
  for (const f of findings) if (!best || RANK[f.severity] > RANK[best]) best = f.severity;
  return best;
}

module.exports = {
  SEVERITY, normalizeForScan, shannonEntropy, locate, decodeOneLayer,
  scanShell, scanInjection, hasHigh, highest,
};
