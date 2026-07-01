# shellter

[![version](https://img.shields.io/badge/version-0.5.3-blue)](CHANGELOG.md)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#installation)
[![tests](https://img.shields.io/badge/tests-394%20passing-brightgreen)](test-hooks.js)

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
- DENY (cross-platform): reverse shells, exfiltration (incl. `tar`/`zip`/`7z` of a secret or whole `.ssh`/`.aws`), encoded payloads, command-exec `git config` keys (`core.hooksPath`/`credential.helper`/`core.sshCommand`/`gpg.program`/`!`-aliases; `user.name`/`user.email` allowed), persistence (shell rc, `.git/hooks/`, CI configs), kernel module load, loader injection (`LD_PRELOAD`/`DYLD_*`), crypto miners, container escape, `rm -rf` of system dirs
- DENY (macOS): `csrutil disable`, `spctl --master-disable`, `launchctl`/LaunchAgents, `security` Keychain extraction, `dscl` user creation, `kextload`, `tccutil reset`, `diskutil erase`, quarantine stripping, `rm -rf /System|/Library|/Applications|/Users|/Volumes`
- DENY (PowerShell): `Remove-Item -Recurse -Force` of home/root/wildcard, `Invoke-Expression`/`iex`, `iwr|iex` and `-OutFile`/`DownloadString` download-exec, EncodedCommand, `Set-ExecutionPolicy`, `Set-MpPreference`, service/scheduled-task/Run-key/`$PROFILE` persistence, lsass MiniDump, secret reads and archive/copy exfil
- DENY (cmd): `del`/`rmdir /s`, `format`, `vssadmin delete shadows`, `bcdedit`, `reg add …\Run`, `schtasks /create`, `sc create`, `net user … /add`, `netsh advfirewall`, `takeown`, `icacls /grant`, `certutil -urlcache`, `bitsadmin /transfer`, `mshta`/`regsvr32`/`rundll32`
- ASK: `git push` to main/`--force`, `git reset --hard`/`clean -f`/`checkout --`, `sudo`, `ssh`/`scp`/`sftp`, SQL `DROP`/`TRUNCATE`, `Start-Process -Verb RunAs`. A hard deny on any segment always wins
- APPROVE (Bash): read-only git plus `pull`/`merge`/`rebase`/`switch`/`blame`/`reflog`; `gh` read-only; `go`/`kubectl get|describe|logs`/`terraform plan|validate`/`helm lint|template`; `ruff`/`black`/`mypy`/`tsc`/`eslint`/`prettier`/`vitest`/`jest`; `pnpm`/`bun` build/test; `pre-commit`/`shellcheck`/`hadolint`/`yamllint`; read-only Unix tools
- APPROVE (PowerShell): read-only verb-noun cmdlets (`Get-*`/`Select-*`/`Test-Path`/`Resolve-Path`/`ConvertTo-Json` …) and aliases (`gci`/`gc`/`ls`/`cat`/`select`/`where` …). `curl`/`wget` excluded here (they alias `Invoke-WebRequest`)
- Mixed/unknown → normal permission prompt

**check-sensitive-files.js** — gates `Read`, `Write`, `Edit`, `Glob`, `Grep`.
- Resolves symlinks first (`ln -s ~/.env /tmp/x; Read /tmp/x` is blocked)
- Blocks `.env*` (`.example`/`.sample`/`.template` excluded), `.pem`, `.key`, `.crt`, `.p12`, `.pfx`, `.ssh/`, `.gnupg/`, `.aws/`, `.azure/`, `.kube/`, and their `.bak`/`.old`/`.backup` variants
- Blocks credential files: `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.cargo/credentials`, `.docker/config.json`, `.config/gh/hosts.yml`, `.ssh/config`
- Blocks wallets/keystores, browser-cookie DBs, macOS Keychain, Windows secrets (`*.ppk`, `NTUSER.DAT`, `SAM`/`SYSTEM` hives, `AppData\…\Credentials`)
- Detects prompt injection in written content: instruction-override, role hijacking, jailbreak personas, role markers (ChatML / Llama / Mistral), fake tool-call tags
- Detects steganographic injection: invisible Unicode, variation-selector smuggling (U+FE00–FE0F / U+E0100–E01EF), interleaved-surrogate re-forming
- Detects homoglyph/mixed-script tokens, line-start fake transcripts, Policy-Puppetry config tags, MCP tool-poisoning blocks, override+exfil co-occurrence, bounded base64/hex decode-one-layer rescan
- Detects encoded eval/exec, polyglot shell substitution in data files, markdown `javascript:`/`data:text/html` URLs, ANSI escapes in source
- Blocks grep patterns that extract secret values or token shapes (AWS keys, GitHub/Slack tokens, JWTs, Bearer)

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
| process substitution | inner command checked; `bash <(curl …)` / `source <(curl …)` denied wholesale |

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

- Deny: add `[/regex/i, 'reason']` to `DENY_PATTERNS` in `check-bash.js`
- Approve: add `/^\s*pattern\b/` to `APPROVE_PATTERNS` (anchor at segment start)
- Sensitive file: extend a path regex in `check-sensitive-files.js` or add one to `pathMatchesAnySensitive`

## Project overrides

`<project>/.claude/settings.local.json` auto-allows patterns without the hook:

```json
{ "permissions": { "allow": ["Bash(cargo test:*)", "Bash(npm run:*)"] } }
```

## Threat model

Defense-in-depth, not a sandbox. Protects against: accidental/LLM-driven dangerous
commands, reads of known sensitive paths (incl. via symlink), written prompt-injection /
fake-tool-call payloads, common bypass wrappers, steganographic Unicode injection.

Does not protect against: TOCTOU symlink races, kernel-level attacks or processes already
running as you, tools other than Bash/Read/Write/Edit/Glob/Grep, brand-new patterns not
yet in the deny list.

A compound command auto-approves only when every subcommand matches an APPROVE pattern
(env-var prefixes stripped). Python heredocs auto-approve only with no dangerous imports,
no `os.system|popen|exec*`, no dynamic eval, and `open()` on literal safe relative paths.

## Troubleshooting

- **Hook not firing** — plugin: check `/plugin list`; manual: `~/.claude/settings.json` needs the `hooks` key with absolute OS-correct paths.
- **False positive** — set `CLAUDE_HOOK_LOG`, reproduce, read the matched reason, adjust the regex or add a project allow rule.
- **Crash / no output** — non-zero exit (except 2) or empty output falls through to the prompt; `CLAUDE_HOOK_DEBUG=1` mirrors decisions to stderr.

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | node ~/.claude/hooks/check-bash.js
node test-hooks.js
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md). Current: 0.5.3 — destructive-rm `/opt` false-positive fix
(deep project paths like `/opt/projs/repo/file.png` allowed; the `/opt` root and `..`
traversal still blocked).
