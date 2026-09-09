# shellter

[![version](https://img.shields.io/badge/version-0.8.0-blue)](CHANGELOG.md)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#installation)
[![tests](https://img.shields.io/badge/tests-738%20passing-brightgreen)](test-hooks.js)

Security hooks that keep AI coding agents from running dangerous commands or leaking
secrets. PreToolUse hooks auto-allow safe operations and block dangerous ones on `Bash`,
PowerShell, and `cmd`. Built for Claude Code; runs under Codex, opencode, pi, and agy via
[adapters](#other-agents). Agents ship no default command blocking, so this is the safety
layer.

## What it does

Two hooks run before every tool call.

**check-bash.js** — gates `Bash` and `PowerShell`. Branches on `tool_name`: Bash gets
Unix parsing, PowerShell gets PS parsing and the PowerShell/cmd rule sets.
- Splits chained commands (`&&`, `||`, `;`) and checks each segment
- Descends into `bash`/`sh`/`zsh`/`dash`/`ash`/`ksh`/`fish -c`, `find -exec`, `xargs`, process substitution, `powershell -Command`/`pwsh -c`/`cmd /c`
- Strips invisible/steganographic Unicode (zero-widths, bidi overrides, tag chars) before matching
- Scans the contents of executed scripts (`bash X`, `./X`, `source X`, `pwsh -File X`, `& ./X.ps1`): reads the resolved file (first 256 KB) for download-pipe-to-shell, dev-tcp reverse shells, base64/xxd decode-then-exec, EncodedCommand/IEX/DownloadString, LOLBins. High-risk + untrusted → `ask`; trusted → allow. See [Script trust](#script-trust)
- DENY (cross-platform): reverse shells (incl. `socat EXEC:`, `nc -c`, `php -r` fsockopen), exfiltration (`tar`/`zip`/`7z` of a secret or whole `.ssh`/`.aws`; `curl -d "$(env)"`/secret-env-var POST to a URL), encoded payloads, *setting* a command-exec `git config` key (`core.hooksPath`/`credential.helper`/`core.sshCommand`/`gpg.program`/`!`-aliases; `user.name`/`user.email` allowed, and reading any key back is allowed), persistence (`.git/hooks/`, CI configs, `~/.ssh/authorized_keys`), kernel module load, loader injection (`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`), crypto miners, container escape, fork bombs, `rm -rf` of system dirs (incl. across a `\`-newline continuation, and `eval "rm -rf /"` / `command eval …`)
- DENY (macOS): `csrutil disable`, `spctl --master-disable`, `launchctl`/LaunchAgents, `security` Keychain extraction, `dscl` user creation, `kextload`, `tccutil reset`, `diskutil erase`, quarantine stripping, `rm -rf /System|/Library|/Applications|/Users|/Volumes`
- DENY (PowerShell): `Remove-Item -Recurse -Force` of home/root/wildcard, `Invoke-Expression`/`iex`, `iwr|iex` and `-OutFile`/`DownloadString` download-exec, EncodedCommand, `Set-ExecutionPolicy`, `Set-MpPreference`, service/scheduled-task/Run-key/`$PROFILE` persistence, lsass MiniDump, secret reads and archive/copy exfil
- DENY (cmd): `del`/`rmdir /s`, `format`, `vssadmin delete shadows`, `bcdedit`, `reg add …\Run`, `schtasks /create`, `sc create`, `net user … /add`, `netsh advfirewall`, `takeown`, `icacls /grant`, `certutil -urlcache`, `bitsadmin /transfer`, `mshta`/`regsvr32`/`rundll32`
- ASK (surfaced for approval, never silently blocked): `git push` to main/`--force`, `git reset --hard`/`clean -f`/`checkout --`, `sudo`, `ssh`/`scp`/`sftp`, SQL `DROP`/`TRUNCATE` (via a SQL client), `Start-Process -Verb RunAs`; and the dual-use shapes moved here from deny — shell-rc writes (`>> ~/.bashrc`, `sed -i ~/.zshrc`), `LD_LIBRARY_PATH`/`DYLD_LIBRARY_PATH`, a generic `eval` / `eval "$(sometool init)"`, `python -c` touching network/`subprocess`/`os.remove`, `dd of=<local file>`, world-writable `chmod` (`777`/`o+w`), `shred`, history tampering (`unset HISTFILE`). A hard deny on any segment always wins
- APPROVE (Bash): read-only git plus `pull`/`merge`/`rebase`/`switch`/`blame`/`reflog`; `gh` read-only; `go`/`kubectl get|describe|logs`/`terraform plan|validate`/`helm lint|template`; `ruff`/`black`/`mypy`/`tsc`/`eslint`/`prettier`/`vitest`/`jest`; `pnpm`/`bun` build/test; `pre-commit`/`shellcheck`/`hadolint`/`yamllint`; read-only Unix tools
- APPROVE (PowerShell): read-only verb-noun cmdlets (`Get-*`/`Select-*`/`Test-Path`/`Resolve-Path`/`ConvertTo-Json` …) and aliases (`gci`/`gc`/`ls`/`cat`/`select`/`where` …). `curl`/`wget` excluded here (they alias `Invoke-WebRequest`)
- Mixed/unknown → normal permission prompt

**check-sensitive-files.js** — gates `Read`, `Write`, `Edit`, `Glob`, `Grep`.
- Resolves symlinks first (`ln -s ~/.env /tmp/x; Read /tmp/x` is blocked)
- Blocks `.env*` (`.example`/`.sample`/`.template` excluded), `.pem`, `.key`, `.p12`, `.pfx`, `.ssh/`, `.gnupg/`, `.aws/`, `.azure/`, `.kube/`, and their `.bak`/`.old`/`.backup` variants. Public `.crt` certificates are not treated as secrets
- Blocks credential files: `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.cargo/credentials`, `.docker/config.json`, `.config/gh/hosts.yml`, `.ssh/config`; and non-code files under a `secrets/`/`credentials/` directory (a source file like `credentials/oauth.ts` is treated as code, not a secret)
- Blocks wallets/keystores, browser-cookie DBs, macOS Keychain, Windows secrets (`*.ppk`, `NTUSER.DAT`, registry hives under a `…\config\` path (`SAM`/`SYSTEM`/`SECURITY` — a repo file named `SECURITY` is not flagged), `AppData\…\Credentials`)
- Prompt-injection detection in written content is **two-tier** (see [Injection-on-write](#injection-on-write)):
  - **Always blocked** (near-zero legitimate use): steganographic Unicode (invisible / tag-char / bidi-override / variation-selector smuggling, U+FE00–FE0F / U+E0100–E01EF, interleaved-surrogate re-forming), an override phrase co-located with an exfil target, MCP tool-poisoning `<IMPORTANT>` blocks, Policy-Puppetry config tags, encoded eval/exec, polyglot shell substitution in data files, markdown `javascript:`/`data:text/html` URLs, ANSI escapes in source
  - **Blocked only when written to an agent-instruction file** (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.clinerules`, `.windsurfrules`, `copilot-instructions.md`, `.mcp.json`, `.claude/**`), since the same text is legitimate in docs, tests, and AI-app source anywhere else: a bare instruction-override / jailbreak / role-hijack phrase, role markers (ChatML / Llama / Mistral), fake tool-call tags, line-start fake transcripts, homoglyph/mixed-script tokens, a lone HTML-comment action
- Both tiers are rescanned across extra views, each behind a cheap prefilter so plain-ASCII content pays nothing: a bounded **two-round** base64/hex decode sharing one token budget (double-encoded payloads no longer evade), an NFKC + confusable fold (a keyword written in fullwidth or Cyrillic/Greek lookalikes folds to ASCII), and **declared-marker reconstruction** — text that says "remove the `%%` markers below" then hides `i%%gn%%ore prev%%ious in%%structions` is reassembled and rescanned
- Blocks grep patterns that extract a concrete secret token shape (AWS keys, GitHub/Slack tokens, JWTs, Bearer) on any path; a `keyword=value` credential search is blocked only across a broad off-project path (`/home`, `~`, a system root) — a self-audit inside your own repo is allowed

## Installation

### Prerequisites

Node.js 18+ on PATH. Claude Code ships as a native binary and does not include Node, so
install it separately if it's missing. Check:

```
node --version
```

If `node` isn't found the hook exits 127, which Claude Code treats as non-blocking — the
tool call runs unprotected. No other dependencies.

### Claude Code plugin (recommended)

```
/plugin marketplace add walangstudio/marketplace
/plugin install shellter@walangstudio
```

Hooks register via `${CLAUDE_PLUGIN_ROOT}`. Update with `/plugin update shellter`. On the
old `walangstudio/shellter` marketplace (pre-0.4.1)? Remove it first
(`/plugin marketplace remove shellter`), then add `walangstudio/marketplace`.

### Manual (Linux / macOS)

```bash
mkdir -p ~/.claude/hooks
cp hooks/check-bash.js hooks/check-sensitive-files.js ~/.claude/hooks/
cp hooks/scan-content.js hooks/shellter-trust.js ~/.claude/hooks/
node merge-settings.js
```

### Manual (Windows)

```powershell
mkdir -Force "$env:USERPROFILE\.claude\hooks"
Copy-Item hooks\check-bash.js,hooks\check-sensitive-files.js "$env:USERPROFILE\.claude\hooks\"
Copy-Item hooks\scan-content.js,hooks\shellter-trust.js "$env:USERPROFILE\.claude\hooks\"
node merge-settings.js "$env:USERPROFILE\.claude\settings.json"
```

`scan-content.js` and `shellter-trust.js` are runtime deps of the two hooks — install all
four. `merge-settings.js` is idempotent and writes forward-slash paths.

## Other agents

Same detector, thin adapters in [`adapters/`](adapters/). Each has its own setup readme.
All shell out to the `node` hooks, so the Node prerequisite applies. Verified via each
host's CLI; app/GUI surfaces use the same hook but are untested.

- Codex CLI (OpenAI, ≥ v0.124.0) — [`adapters/codex`](adapters/codex/README.md)
- Antigravity / `agy` (Google) — [`adapters/agy`](adapters/agy/README.md)
- opencode (experimental) — [`adapters/opencode`](adapters/opencode/README.md)
- pi — [`adapters/pi`](adapters/pi/README.md)

## Hook protocol

JSON on stdin, JSON on stdout.

```json
// in
{ "tool_name": "Bash", "tool_input": { "command": "git status && npm test" } }
// out
{ "hookSpecificOutput": { "hookEventName": "PreToolUse",
  "permissionDecision": "allow", "permissionDecisionReason": "Auto-approved by hook" } }
```

`permissionDecision`: `allow` (no prompt), `deny` (blocked, reason shown), `ask` (force
the prompt). Exit `0` = structured decision or fallthrough; exit `2` = hard block (stderr
shown).

## Recursive wrapper checking

| Wrapper | Behaviour |
| --- | --- |
| `bash -c '…'` / `sh -c` | inner command parsed, deny/approve recurses per segment |
| `bash -c "$(curl …)"` | denied — opaque payload |
| `find … -exec CMD … \;` | `CMD` parsed and checked |
| `xargs … CMD` | `CMD` parsed and checked |
| process substitution | inner command checked; `bash <(curl …)` and `source <(curl/wget/base64 …)` denied; `source <(kubectl completion …)` and other local generators allowed |

## Script trust

`bash install.sh` hides what the script does, so shellter reads it (first 256 KB) and
scans the contents. High-risk + untrusted → `ask` naming the matched pattern and line.
Clean scripts pass; only high-confidence shapes trigger `ask`.

Stop the prompt for a reviewed script:

1. Pick **"Yes, don't ask again"** — shellter honors the resulting allow-rule.
2. Trust by content hash:

```bash
node ~/.claude/hooks/shellter-trust.js add ./install.sh
node ~/.claude/hooks/shellter-trust.js list
node ~/.claude/hooks/shellter-trust.js remove <hash|path>
```

Trust survives move/rename; editing the script invalidates it. Store at
`~/.claude/shellter-trust.json` (override with `SHELLTER_TRUST_FILE`). If a build doesn't
surface `ask` reasons, set `SCRIPT_RISK_DECISION` in `check-bash.js` to `'deny'`.

## Injection-on-write

A file an agent later reads as instructions is a live attack surface — a payload written
into `CLAUDE.md` can hijack the next turn. An ordinary file is not: a security write-up, a
test fixture, a chatbot's system-prompt string, and an example `User:` / `Assistant:`
transcript all legitimately contain the same phrases. So the injection scan on writes is
two-tier, and the second tier is gated on the destination:

- **Class A — always denied.** Signals with near-zero legitimate use: steganographic
  Unicode; an override phrase sitting next to an exfil target (an `.ssh` key path, `.env`,
  cloud credentials); MCP tool-poisoning `<IMPORTANT>` blocks; Policy-Puppetry config tags.
- **Class B — denied only on an agent-instruction file.** A bare override / jailbreak /
  role-hijack phrase, a role marker (ChatML / Llama / Mistral), a fake tool-call tag, a
  fake transcript, a homoglyph token, a lone HTML-comment action. Instruction files are
  `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.clinerules`, `.windsurfrules`,
  `copilot-instructions.md`, `.mcp.json`, and anything under `.claude/`. Anywhere else these
  fall through to the normal permission prompt instead of being blocked.

The same gate covers content written through the shell (`echo … > CLAUDE.md`, `cat <<EOF`
heredocs), not just the `Write`/`Edit`/`MultiEdit`/`NotebookEdit` tools.

## Audit log

Off by default. Set `CLAUDE_HOOK_LOG` to a writable path for one JSON line per decision;
`CLAUDE_HOOK_DEBUG=1` mirrors to stderr. The directory must exist; write errors are
silent.

```bash
CLAUDE_HOOK_LOG=/tmp/hook.log claude
```

```powershell
$env:CLAUDE_HOOK_LOG = "$env:TEMP\hook.log"; claude
```

Forward slashes work on Windows (Node normalizes them).

## Custom patterns

- Deny / ask: add `[/regex/i, 'reason']` (hard deny) or `[/regex/i, 'reason', 'ask']` (surface for approval) to `DENY_PATTERNS` in `check-bash.js`. A matcher may also be a predicate function returning a reason string (see `rmDanger`)
- Approve: add `/^\s*pattern\b/` to `APPROVE_PATTERNS` (anchor at segment start)
- Sensitive file: extend a path regex in `check-sensitive-files.js` or add one to `pathMatchesAnySensitive`
- Agent-instruction file (the destinations that gate Class-B injection on writes): extend `AGENT_INSTRUCTION_FILE` in `scan-content.js`

## Project overrides

`<project>/.claude/settings.local.json` auto-allows patterns without the hook:

```json
{ "permissions": { "allow": ["Bash(cargo test:*)", "Bash(npm run:*)"] } }
```

## Threat model

Defense-in-depth, not a sandbox. Protects against: accidental/LLM-driven dangerous
commands, reads of known sensitive paths (incl. via symlink), prompt-injection /
fake-tool-call payloads written to an agent-instruction file (or carrying an exfil target),
common bypass wrappers, steganographic Unicode injection.

Design choice, not a gap: a bare injection phrase written to an ordinary (non-instruction)
file is intentionally allowed — blocking it hard-blocked security docs, tests, and AI-app
source, and the payload is only dangerous where an agent auto-ingests it (see
[Injection-on-write](#injection-on-write)).

Does not protect against: TOCTOU symlink races, kernel-level attacks or processes already
running as you, tools other than Bash/Read/Write/Edit/Glob/Grep, brand-new patterns not
yet in the deny list.

**shellter fails open.** If `node` is not on the PATH Claude Code launches hooks with, the
hook exits 127 and Claude Code treats that as non-blocking — the tool call runs unchecked.
Two consequences worth knowing:

- A broad allow rule turns that into silence. With `Read(*)` / `Write(*)` / `Bash(*)` in
  `permissions.allow`, or `defaultMode` set to auto-accept, any verdict shellter does *not*
  produce is an automatic allow rather than a prompt. Grant narrow rules, not wildcards.
  Through 0.7.1 the manual installer added exactly those wildcards for the file tools. As
  of 0.8.0 it does not, and it no longer overwrites your existing allow list — but **it
  cannot clean up an install you already have.** If you ran an older manual installer,
  those seven entries are still in your `settings.json`; re-running `merge-settings.js`
  now warns about them and names the file, and you remove the ones you did not add
  yourself. Plugin installs were never affected.
- When shellter cannot fully analyze a command — an undecodable script, a parse failure —
  it now returns `ask` rather than staying silent, so an unexamined command still stops at
  a prompt. A ceiling is a safety boundary, not evidence the part it skipped was clean.

A compound command auto-approves only when every subcommand matches an APPROVE pattern
(env-var prefixes stripped). Python heredocs auto-approve only with no dangerous imports,
no `os.system|popen|exec*`, no dynamic eval, and `open()` on literal safe relative paths.

## Bundle audit (`shellter scan`)

The two hooks guard what the agent *emits*. Nothing guarded what the agent is *given*: a
plugin's `SKILL.md` is loaded straight into context, its `hooks.json` runs on lifecycle
events before any tool call, and its `.mcp.json` points at a server whose tool descriptions
the model reads as instructions. None of that passes through a PreToolUse hook.

```
npm run scan -- path/to/plugin          # or: node hooks/shellter-scan.js <path> [--json]
```

Exits 1 on any high-severity finding, so it drops into a pre-install check or CI. `--strict`
also exits 1 when anything went uninspected: a skipped dependency tree, a symlink, an
oversize file, a depth or file limit. Those are always listed under NOT INSPECTED, because
a clean result over an unwalked subtree is not evidence of anything.

| rule | what it looks for |
|---|---|
| `BH1` | bundle ships hooks; ambient matchers (`*`, empty) rank higher |
| `BH2` | a shipped hook command posts to a non-loopback URL, or contains shell malice |
| `BH3` | shipped `settings.json` with blanket `permissions.allow` or a bypassing `defaultMode` |
| `LP2` | `allowed-tools` granting every tool, a tool unrestricted, or scoping to an interpreter that runs arbitrary code |
| `AS1` | bundle reads `.claude/`, `mcp.json`, another agent's config, or a peer skill's `SKILL.md` |
| `SC1` / `SC2` | MCP server launched from an unpinned package, or over plaintext `http` |
| `INJ` / `SH` | the full injection and shell-malice scanners over the bundle's own files, including `secret-read-uploaded` (a script that reads a secret and posts it out) |

A bundle is untrusted by definition, so **both** injection tiers are reported here - the
agent-instruction-file gate used on the write path does not apply, because every file in a
skill bundle is in effect an instruction file.

It is deliberately a CLI, not a hook: the result only changes at install time, so paying a
directory walk on every session start would be latency for nothing.

**Scope.** This is triage - what a zero-dependency file walker does well. No AST, no taint
analysis, no YARA, no vulnerability database, and it cannot read the tool descriptions a
running MCP server serves. For that depth use NVIDIA's
[SkillSpector](https://github.com/NVIDIA/skillspector), which is built for it.

Scanning a security tool with a security tool lights up: shellter's own detector source
contains the literal patterns it matches, and its test corpus contains attack strings by
design. That is expected. shellter does **not** exempt its own files - a self-exemption was
tried once and reverted as a confirmed security regression.

## Troubleshooting

- **Hook not firing** — plugin: check `/plugin list`; manual: `~/.claude/settings.json` needs the `hooks` key with absolute OS-correct paths.
- **False positive** — set `CLAUDE_HOOK_LOG`, reproduce, read the matched reason, adjust the regex or add a project allow rule.
- **Crash / no output** — non-zero exit (except 2) or empty output falls through to the prompt; `CLAUDE_HOOK_DEBUG=1` mirrors decisions to stderr.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | node ~/.claude/hooks/check-bash.js
node test-hooks.js
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Current: 0.8.0 — closes a cross-segment variable-indirection
bypass that auto-approved secret reads (`X=.env; cat $X`), adds a coverage gate so a command
the engine could not fully analyze degrades to `ask` instead of falling through, and stops the
manual installer granting blanket file-tool permissions. Previously 0.7.1 — two false-positive fixes: `git config <key>`
reads (auditing a hooks-path backdoor is not setting one) and `jq`/`rg`/`sed` filter arguments
(a `.key` selector is not a private key). Previously 0.7.0 — false-positive reduction + correctness
hardening: injection-on-write now denies only agent-instruction files or exfil-carrying
payloads (security docs, test fixtures, chatbot prompts, Q&A transcripts stop being blocked);
PowerShell rules no longer fire on Bash (`grep -w hidden`, Elixir `iex`); shell idioms
un-blocked or moved to `ask` (`eval "$(ssh-agent)"`, `source <(… completion)`, `>> ~/.bashrc`,
`LD_LIBRARY_PATH`, `crontab -l`, VCS-URL installs, `python -c` network one-liners, `dd of=file`,
pager pipelines); narrowed secret tokens (public `.crt`, `credentials/` source dirs, bare
`SECURITY` files, keyword self-audit greps); and new hard denies for the eval-launder auto-approve
(`command eval "rm -rf /"`), `chmod` world-writable, `$(env)` curl exfil, php/socat/`nc -c`
reverse shells, fork bombs, and backslash-newline'd `rm`.
