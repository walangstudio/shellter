#!/usr/bin/env node
'use strict';
// shellter scan -- pre-install audit of a skill / plugin / MCP bundle.
//
// The two PreToolUse hooks guard what the agent EMITS. Nothing guarded what the agent is
// GIVEN: a plugin's SKILL.md is loaded straight into context, its hooks.json runs on
// lifecycle events before any tool call happens, and its .mcp.json points at a server whose
// tool descriptions the model reads as instructions. None of that passes through a
// PreToolUse hook, so none of it was ever inspected. This closes that.
//
// Deliberately a CLI, not a hook: the result only changes at install time, so paying the
// walk on every session start would be latency for nothing.
//
// Scope is what a zero-dependency file walker can do WELL. No AST, no taint analysis, no
// YARA, no vulnerability database. For that depth run NVIDIA's SkillSpector, which is built
// for it; this is the fast triage you run before you decide to care.

const fs = require('fs');
const path = require('path');
const scan = require('./scan-content.js');

// Bounds. A bundle is untrusted input, so the walk is capped in every dimension.
const MAX_FILES = 2000;
// Generous on purpose: this runs once before an install, not on a hot path, and a 1 MB cap
// made "pad the file past the limit" a one-line way to go uninspected.
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 12;
// Only dependency, VCS and cache trees are skipped. `dist`, `build`, `target` and `vendor`
// are deliberately NOT here: for a pre-install audit those hold the shipped code that will
// actually run, so skipping them is the linter convention applied to the wrong question.
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__',
                           '.tox', '.pytest_cache', '.mypy_cache']);
const TEXT_EXT = /\.(md|markdown|json|ya?ml|toml|sh|bash|zsh|ps1|psm1|js|mjs|cjs|ts|py|rb|txt)$/i;

const SEV_RANK = { high: 3, medium: 2, low: 1 };

// Every skip is recorded. For a pre-install audit that exits 1 on a high finding, an
// unwalked subtree is an evasion, not a perf win: a payload in dist/ or behind a symlink
// would otherwise produce "no findings, exit 0" with nothing saying we never looked.
function walk(root) {
  const out = [];
  const stack = [[root, 0]];
  const gaps = [];
  const noteGap = (kind, where) => {
    const d = kind + ': ' + where;
    if (gaps.length < 24 && !gaps.includes(d)) gaps.push(d);
  };
  while (stack.length) {
    const [dir, depth] = stack.pop();
    const relDir = path.relative(root, dir).replace(/\\/g, '/') || '.';
    if (depth > MAX_DEPTH) { noteGap('depth limit', relDir); continue; }
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { noteGap('unreadable directory', relDir); continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      const rel = path.relative(root, full).replace(/\\/g, '/');
      if (e.isSymbolicLink()) { noteGap('symlink not followed', rel); continue; }
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) { noteGap('directory skipped', rel); continue; }
        stack.push([full, depth + 1]);
      } else if (e.isFile()) {
        if (out.length >= MAX_FILES) { noteGap('file limit reached', rel); continue; }
        out.push(full);
      }
    }
  }
  return { files: out, gaps };
}

// Returns { text } when readable, or { skip } naming why. Oversize is NOT the same as
// binary: padding a SKILL.md past the cap would otherwise be a one-line evasion reported
// as "skipped (binary/non-text)".
function readText(file) {
  try {
    const st = fs.statSync(file);
    if (st.size > MAX_FILE_BYTES) return { skip: 'over size cap (' + Math.round(st.size / 1024) + 'KB)' };
    const buf = fs.readFileSync(file);
    for (let i = 0; i < buf.length; i++) if (buf[i] === 0) return { skip: null };   // binary
    return { text: buf.toString('utf8') };
  } catch (e) { return { skip: 'unreadable (' + ((e && e.code) || 'error') + ')' }; }
}

// ---- structural checks -------------------------------------------------------

// A non-loopback URL next to an upload verb. Two-token co-occurrence, not dataflow:
// enough to say "this hook can post somewhere", which is the thing worth a human look.
const LOOPBACK = /^https?:\/\/(?:127\.\d+\.\d+\.\d+|\[?::1\]?|localhost)(?::\d+)?(?:[/?#]|$)/i;
const URL_RE = /\bhttps?:\/\/[^\s'"`)\]}]+/gi;
const UPLOAD_VERB =
  /\bcurl\b[^\n]{0,200}(?:\s-d\b|\s--data|\s-F\b|\s--form|\s-T\b|\s--upload-file)|\bwget\b[^\n]{0,200}--post|Invoke-RestMethod[^\n]{0,200}-Method\s+Post|Invoke-WebRequest[^\n]{0,200}-Method\s+Post|\bfetch\s*\([^\n]{0,200}method\s*:\s*['"]POST/i;

function remoteUrls(text) {
  return (text.match(URL_RE) || []).filter((u) => !LOOPBACK.test(u));
}

const AMBIENT_MATCHER = /^(?:\*|\.\*|)$/;

function checkHooksManifest(rel, text, add) {
  let obj;
  try { obj = JSON.parse(text); } catch { return; }
  const hooks = obj && obj.hooks;
  if (!hooks || typeof hooks !== 'object') return;
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    for (const g of groups) {
      const matcher = g && typeof g.matcher === 'string' ? g.matcher : '';
      const ambient = AMBIENT_MATCHER.test(matcher.trim());
      add({
        rule: 'BH1', severity: ambient ? 'medium' : 'low', file: rel,
        detail: 'ships a ' + event + ' hook' + (matcher ? ' (matcher: ' + matcher + ')' : ' (no matcher: fires on everything)'),
      });
      for (const h of (Array.isArray(g && g.hooks) ? g.hooks : [])) {
        if (!h) continue;
        // `commandWindows` is what actually runs on Windows -- shellter's own hooks.json
        // uses it. Reading only `command` lets a bundle put the payload in the variant
        // that executes and stay invisible.
        for (const key of ['command', 'commandWindows', 'commandUnix']) {
          const cmd = typeof h[key] === 'string' ? h[key] : '';
          if (!cmd) continue;
          const where = event + ' hook ' + key;
          const urls = remoteUrls(cmd);
          if (urls.length && UPLOAD_VERB.test(cmd)) {
            add({ rule: 'BH2', severity: 'high', file: rel,
                  detail: where + ' posts to ' + urls[0] });
          }
          const sh = scan.scanShell(cmd, { decode: true }).filter((f) => f.severity === 'high');
          if (sh.length) {
            add({ rule: 'BH2', severity: 'high', file: rel, detail: where + ': ' + sh[0].signal });
          }
        }
      }
    }
  }
}

// A bare tool name grants EVERY invocation of it -- `"Bash"` is broader than `"Bash(*)"`
// is explicit about. Matching only the parenthesised form missed the actual blanket grant.
const WILDCARD_ALLOW = /^(?:\*|[A-Za-z]+(?:\(\s*\*\s*\))?)$/;

function checkSettings(rel, text, add) {
  let obj;
  try { obj = JSON.parse(text); } catch { return; }
  const perms = obj && obj.permissions;
  if (perms && typeof perms.defaultMode === 'string' &&
      /bypass|acceptEdits|dontAsk/i.test(perms.defaultMode)) {
    add({ rule: 'BH3', severity: 'high', file: rel,
          detail: 'ships defaultMode "' + perms.defaultMode + '"' });
  }
  const allow = perms && Array.isArray(perms.allow) ? perms.allow : [];
  const wild = allow.filter((r) => typeof r === 'string' && WILDCARD_ALLOW.test(r.trim()));
  if (wild.length) {
    add({ rule: 'BH3', severity: 'high', file: rel,
          detail: 'ships blanket permissions: ' + wild.join(' ') });
  }
}

function checkMcpConfig(rel, text, add) {
  let obj;
  try { obj = JSON.parse(text); } catch { return; }
  const servers = obj && (obj.mcpServers || obj.servers);
  if (!servers || typeof servers !== 'object') return;
  for (const [name, s] of Object.entries(servers)) {
    if (!s || typeof s !== 'object') continue;
    const argv = [s.command].concat(Array.isArray(s.args) ? s.args : []).filter(Boolean).join(' ');
    // An unpinned remote fetch-and-run is the npm/PyPI supply-chain shape: whatever the
    // registry serves at install time is what executes, and it can change under you.
    if (/\b(?:npx|bunx|pnpm\s+dlx|uvx|pipx\s+run)\b/.test(argv) && !/@\d|==\d/.test(argv)) {
      add({ rule: 'SC1', severity: 'medium', file: rel,
            detail: 'MCP server "' + name + '" runs an unpinned package: ' + argv.slice(0, 120) });
    }
    if (typeof s.url === 'string' && /^http:\/\//i.test(s.url) && !LOOPBACK.test(s.url)) {
      add({ rule: 'SC2', severity: 'medium', file: rel,
            detail: 'MCP server "' + name + '" uses plaintext http: ' + s.url });
    }
  }
}

// A skill declaring it may run anything, or reading the agent's own configuration, is
// asking for capability it usually does not need. Frontmatter is read line-wise on purpose:
// a YAML parser is a dependency, and this only needs the top of the file.
function frontmatter(text) {
  if (!/^---\r?\n/.test(text)) return null;
  const end = text.indexOf('\n---', 4);
  return end === -1 ? null : text.slice(4, end);
}

function checkSkillFrontmatter(rel, text, add) {
  const fm = frontmatter(text);
  if (fm === null) return;
  // `\s*` after the colon swallows a newline, so an inline regex captures only the FIRST
  // item of a YAML block list and misses a `- Bash` further down. Collect the inline value
  // AND any following `- item` lines, then reason over the whole set.
  const lines = fm.split(/\r?\n/);
  const at = lines.findIndex((l) => /^allowed-tools\s*:/i.test(l));
  if (at === -1) return;
  const parts = [lines[at].replace(/^allowed-tools\s*:/i, '').trim()];
  for (let i = at + 1; i < lines.length; i++) {
    const item = /^\s*-\s*(.+?)\s*$/.exec(lines[i]);
    if (!item) break;
    parts.push(item[1]);
  }
  const v = parts.filter(Boolean).join(', ').trim();
  if (!v) return;
  const short = v.slice(0, 80);
  // Precision matters here or the rule cries wolf. `Bash(node *)` is SCOPED to node -- a
  // bare `*` inside a tool's argument pattern is not the same as granting every tool.
  if (/(?:^|[\s,\[])\*(?:[\s,\]]|$)/.test(v)) {
    add({ rule: 'LP2', severity: 'high', file: rel,
          detail: 'allowed-tools grants every tool: ' + short });
  } else if (/\b[A-Za-z]+\(\s*\*\s*\)/.test(v) ||
             /(?:^|[\s,\[])(?:Bash|PowerShell)(?:[\s,\]]|$)/.test(v)) {
    add({ rule: 'LP2', severity: 'high', file: rel,
          detail: 'allowed-tools grants a tool unrestricted: ' + short });
  } else {
    // Scoped, but scoped to something that runs arbitrary code anyway: `Bash(node *)`
    // permits `node -e "<anything>"`. Worth surfacing, not worth calling unrestricted.
    const interp = /\b(?:Bash|PowerShell)\s*\(\s*(?:[^)]*[/\\])?(node|deno|bun|python[23]?|perl|ruby|php|sh|bash|zsh|npx|bunx|uvx|pnpm|eval)\b/i.exec(v);
    if (interp) {
      add({ rule: 'LP2', severity: 'medium', file: rel,
            detail: 'allowed-tools is scoped to ' + interp[1] +
                    ', which can run arbitrary code: ' + short });
    }
  }
}

// Reading another agent's configuration, or a peer skill's instructions, is how one
// bundle escalates through another. SkillSpector calls this class agent snooping.
const SNOOP = [
  [/(?:^|[\s'"`(/])~?[./\\]*\.claude[/\\](?!plugins[/\\])/i, 'reads the agent config directory (.claude/)'],
  [/\.?mcp\.json\b/i, 'reads MCP server configuration (mcp.json)'],
  [/(?:^|[\s'"`(/])~?[./\\]*\.(?:codex|gemini|cursor|aider)[/\\]/i, 'reads another agent tool config'],
  [/skills[/\\][^\s'"`]*[/\\]SKILL\.md/i, "reads a peer skill's SKILL.md"],
  [/\.claude[/\\]settings(?:\.local)?\.json/i, 'reads agent settings.json'],
];

function checkSnooping(rel, text, add) {
  for (const [re, detail] of SNOOP) {
    if (re.test(text)) add({ rule: 'AS1', severity: 'medium', file: rel, detail });
  }
}

// ---- main --------------------------------------------------------------------

function scanBundle(root) {
  const findings = [];
  const seen = new Set();
  const add = (f) => {
    const key = f.rule + '|' + f.file + '|' + f.detail;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  const { files, gaps } = walk(root);
  let inspected = 0;
  let skipped = 0;
  const noteGap = (d) => { if (gaps.length < 24 && !gaps.includes(d)) gaps.push(d); };

  for (const file of files) {
    const rel = path.relative(root, file).replace(/\\/g, '/');
    const base = path.basename(file).toLowerCase();
    const isText = TEXT_EXT.test(file) || base === 'skill.md';
    if (!isText) { skipped++; continue; }
    const r = readText(file);
    if (r.skip !== undefined) {
      skipped++;
      if (r.skip) noteGap(r.skip + ': ' + rel);   // null = ordinary binary, not a gap
      continue;
    }
    const text = r.text;
    inspected++;

    // A bundle is untrusted by definition, so BOTH injection tiers are reported here.
    // The agent-instruction-file gate the write path uses does not apply: every file in a
    // skill bundle is, in effect, an instruction file.
    for (const f of scan.scanInjection(text, { decode: true })) {
      if (f.severity === 'low') continue;
      add({ rule: 'INJ', severity: f.severity, file: rel,
            detail: f.signal + (f.line ? ' (line ' + f.line + ')' : '') });
    }
    if (/\.(sh|bash|zsh|ps1|psm1)$/i.test(file)) {
      for (const f of scan.scanShell(text, { decode: true })) {
        if (f.severity !== 'high') continue;
        add({ rule: 'SH', severity: 'high', file: rel,
              detail: f.signal + (f.line ? ' (line ' + f.line + ')' : '') });
      }
    }
    // settings.json is the canonical place Claude Code hooks live, so it needs the hook
    // check too -- gating BH2 on hooks.json alone left the tool's highest-value rule blind
    // at the most likely location.
    if (base === 'hooks.json' || base === 'plugin.json' ||
        base === 'settings.json' || base === 'settings.local.json') {
      checkHooksManifest(rel, text, add);
    }
    if (base === 'settings.json' || base === 'settings.local.json') checkSettings(rel, text, add);
    if (base === '.mcp.json' || base === 'mcp.json') checkMcpConfig(rel, text, add);
    // allowed-tools frontmatter is not unique to SKILL.md: a plugin's commands/*.md and
    // agents/*.md carry the same grant, so gating on the filename missed it entirely.
    if (/\.(md|markdown)$/i.test(file)) checkSkillFrontmatter(rel, text, add);
    checkSnooping(rel, text, add);
  }

  findings.sort((a, b) => (SEV_RANK[b.severity] - SEV_RANK[a.severity]) ||
                          a.rule.localeCompare(b.rule) || a.file.localeCompare(b.file));
  return { findings, inspected, skipped, gaps, total: files.length };
}

module.exports = { scanBundle, walk, remoteUrls };

// ---- CLI ---------------------------------------------------------------------

if (require.main === module) {
  const args = process.argv.slice(2);
  const json = args.includes('--json');
  // Mirrors SkillSpector --fail-on-incomplete: a partial walk should be able to fail a
  // gate, since a clean result over an unwalked subtree is not evidence of anything.
  const strict = args.includes('--strict');
  const target = args.find((a) => !a.startsWith('-'));
  if (!target) {
    console.error('usage: shellter-scan.js <path-to-bundle> [--json]');
    console.error('  Audits a skill/plugin/MCP bundle before you trust it.');
    console.error('  Exit 1 if any high-severity finding is present.');
    console.error('  --strict also exits 1 when any file or directory went uninspected.');
    process.exit(2);
  }
  let root;
  try {
    root = fs.realpathSync(path.resolve(target));
    if (!fs.statSync(root).isDirectory()) throw new Error('not a directory');
  } catch (e) {
    console.error('cannot scan ' + target + ': ' + (e && e.message));
    process.exit(2);
  }

  const r = scanBundle(root);
  const high = r.findings.filter((f) => f.severity === 'high');

  if (json) {
    console.log(JSON.stringify({ target: root, ...r, highCount: high.length }, null, 2));
  } else {
    console.log('shellter scan: ' + root);
    console.log('  ' + r.inspected + ' files inspected, ' + r.skipped + ' skipped (binary/non-text)');
    if (!r.findings.length) {
      console.log('\n  no findings.');
    } else {
      let sev = null;
      for (const f of r.findings) {
        if (f.severity !== sev) { sev = f.severity; console.log('\n  ' + sev.toUpperCase()); }
        console.log('    [' + f.rule + '] ' + f.file + ' -- ' + f.detail);
      }
    }
    // Named, not summarised: "we did not look at dist/" is the sentence that stops a clean
    // exit code from being mistaken for a clean bundle.
    if (r.gaps.length) {
      console.log('\n  NOT INSPECTED');
      for (const g of r.gaps) console.log('    ' + g);
    }
    console.log('\n  ' + high.length + ' high, ' +
                r.findings.filter((f) => f.severity === 'medium').length + ' medium.');
    if (r.gaps.length) {
      console.log('  Coverage was partial: a clean result here is not evidence the rest is clean.');
    }
    console.log('  Triage only -- no AST, taint, or vulnerability-database analysis.');
    console.log('  For a deep audit see NVIDIA SkillSpector: https://github.com/NVIDIA/skillspector');
  }
  process.exit(high.length || (strict && r.gaps.length) ? 1 : 0);
}
