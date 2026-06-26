# shellter

[![version](https://img.shields.io/badge/version-0.3.0-blue)](CHANGELOG.md)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#installation)
[![tests](https://img.shields.io/badge/tests-324%20passing-brightgreen)](test-hooks.js)

Shelters you from dangerous shell commands. Global PreToolUse hooks that
auto-allow safe operations and block dangerous ones across every Claude Code
session, on the `Bash` tool (Linux, macOS, Git-Bash, WSL) and the `PowerShell`
tool (Windows). Claude Code ships no default dangerous-command blocking, so
these hooks are the safety layer.

## What It Does

Two Node.js hooks run before every tool call:

**check-bash.js** gates the `Bash` and `PowerShell` tools. It branches on
`tool_name`: Bash commands keep full Unix/macOS parsing; PowerShell commands get
PowerShell parsing (backtick escape, PS quoting) and the PowerShell/cmd rule sets.
- Splits chained commands (`&&`, `||`, `;`) and checks each segment
- Recursively descends into `bash`/`sh`/`zsh`/`dash`/`ash`/`ksh`/`fish -c '...'`, `find -exec`, `xargs`, `<(...)` / `>(...)`, and any `powershell -Command` / `pwsh -c` / `cmd /c` shelled out from a command, so wrappers can't hide a payload
- Strips invisible/steganographic Unicode (zero-widths, bidi overrides, tag chars) before matching
- **Scans the CONTENTS of executed scripts** (`bash`/`sh`/`zsh`/… `X`, `./X`, `source X` / `. X`, `powershell`/`pwsh -File X`, `& ./X.ps1`): reads the resolved file (first 256 KB) and looks for download-pipe-to-shell, `/dev/tcp` reverse shells, base64/xxd decode-then-exec, `-EncodedCommand`/`IEX`/`DownloadString`, and LOLBins. High-risk + untrusted → `ask` ("read this script yourself"); trusted → silent allow. See [Script trust store](#script-trust-store)
- DENY (cross-platform): reverse shells, exfiltration, encoded payloads, privilege escalation, identity backdoors via `git config`, persistence (shell rc / `.git/hooks/` / CI configs), kernel module load, loader injection (`LD_PRELOAD`/`DYLD_*`), crypto miners, container escape, force-push to main (incl. `git --no-pager`/`-C` prefixes), `rm -rf` of system dirs, and more
- DENY (macOS): `csrutil disable`, `spctl --master-disable`, `launchctl`/LaunchAgents persistence, `security` Keychain extraction, `dscl` user creation, `kextload`, `tccutil reset`, `diskutil erase`, quarantine stripping, `rm -rf /System|/Library|/Applications|/Users|/Volumes`
- DENY (PowerShell): `Remove-Item -Recurse -Force` of home/root/wildcard, `Invoke-Expression`/`iex`, `iwr|iex` and `-OutFile`/`DownloadString` download-exec, `-EncodedCommand`, `Set-ExecutionPolicy`, Defender tamper (`Set-MpPreference`), service/scheduled-task/Run-key/`$PROFILE` persistence, `Start-Process -Verb RunAs`, lsass MiniDump
- DENY (cmd.exe): `del`/`rmdir /s`, `format`, `vssadmin delete shadows`, `bcdedit`, `reg add …\Run`, `schtasks /create`, `sc create`, `net user … /add`, `netsh advfirewall`, `takeown`, `icacls /grant`, `certutil -urlcache`, `bitsadmin /transfer`, `mshta`/`regsvr32`/`rundll32` LOLBins
- APPROVE (Bash): read-only git plus `pull` / `merge` / `rebase` / `switch` / `blame` / `reflog`; `gh` read-only; `go` / `kubectl get|describe|logs` / `terraform plan|validate` / `helm lint|template`; `ruff` / `black` / `mypy` / `tsc` / `eslint` / `prettier` / `vitest` / `jest`; `pnpm` / `bun` build/test; `pre-commit` / `shellcheck` / `hadolint` / `yamllint`; standard read-only Unix tools
- APPROVE (PowerShell): read-only verb-noun cmdlets (`Get-*`/`Select-*`/`Test-Path`/`Resolve-Path`/`ConvertTo-Json` …) and their canonical aliases (`gci`/`gc`/`ls`/`cat`/`select`/`where` ...). The bash `curl`/`wget` auto-approve is deliberately excluded here, because on PowerShell those alias `Invoke-WebRequest`
- Mixed/unknown: falls through to the normal Claude Code permission prompt

**check-sensitive-files.js** gates Read, Write, Edit, Glob, Grep:
- Resolves symlinks before checking, so `ln -s ~/.env /tmp/x; Read /tmp/x` is blocked
- Blocks access to `.env*`, `.pem`, `.key`, `.crt`, `.p12`, `.pfx`, `.ssh/`, `.gnupg/`, `.aws/`, `.azure/`, `.kube/`, plus their `.bak` / `.old` / `.backup` variants
- Blocks read of credential files: `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.cargo/credentials`, `.docker/config.json`, `.config/gh/hosts.yml`, `.ssh/config`
- Blocks wallet / keystore / browser-cookie databases, macOS Keychain (`Library/Keychains/`, `login.keychain-db`, `System.keychain`), and Windows secrets (`*.ppk`, `NTUSER.DAT`, `SAM`/`SYSTEM` hives, `AppData\…\Microsoft\Credentials`)
- Detects prompt-injection in written content: instruction-override phrases, role hijacking ("pretend you are", "assume the role of", "from now on you are"), jailbreak ("DAN mode", "developer mode"), role-tag injection (`<|im_start|>system`, `[SYSTEM]`, `[INST]`)
- Detects fake tool-call tags (`<function_calls>`, `<invoke>`) in written content
- Detects steganographic injection: invisible Unicode characters in source files, plus **variation-selector smuggling** (U+FE00–FE0F / U+E0100–E01EF — evades many commercial detectors) and a recursive strip that survives interleaved-surrogate re-forming
- Detects 2025-2026 injection shapes: **homoglyph / mixed-script** tokens, broadened role markers (ChatML / Llama / Mistral / line-start `System:`+`Assistant:` fake transcripts), **Policy-Puppetry** config tags, **MCP tool-poisoning** `<IMPORTANT>` blocks, override-phrase + exfil-target co-occurrence, and a bounded **base64/hex decode-one-layer-then-rescan**
- Detects encoded eval/exec, polyglot shell substitution in data files (incl. `.json.bak` / `.yaml.old`), markdown `javascript:` / `data:text/html` URLs, and ANSI-escape sequences in source files
- Blocks grep patterns that extract literal secret values or known token shapes (AWS access keys, GitHub tokens, Slack tokens, JWTs, Bearer tokens)

## File Layout

```
~/.claude/
  settings.json           # hooks registration + global permissions
  shellter-trust.json     # content-hash trust store for risky scripts (auto-created)
  hooks/
    check-bash.js         # bash/powershell command gatekeeper
    check-sensitive-files.js  # file access gatekeeper
    scan-content.js       # shared scanner (shell-malice + prompt-injection)
    shellter-trust.js     # trust store + CLI (add/list/remove)
```

`scan-content.js` and `shellter-trust.js` are runtime dependencies of the two
hooks; install all four together. Project-specific overrides go in
`<project>/.claude/settings.local.json`.

## Installation

### Prerequisites

Node.js >= 18 (Claude Code requires Node.js 18+, so it's already installed if you have Claude Code).

No other dependencies. Hooks use only Node.js built-ins.

### Linux / macOS

```bash
# 1. Copy hook scripts (all four -- the last two are runtime deps)
mkdir -p ~/.claude/hooks
cp hooks/check-bash.js hooks/check-sensitive-files.js ~/.claude/hooks/
cp hooks/scan-content.js hooks/shellter-trust.js ~/.claude/hooks/

# 2. Merge into existing settings (safe to run multiple times).
#    Substitutes __HOME__ -> $HOME, prints the sha256 of each installed hook.
node merge-settings.js
```

### Windows

```powershell
mkdir -Force "$env:USERPROFILE\.claude\hooks"
Copy-Item hooks\check-bash.js,hooks\check-sensitive-files.js "$env:USERPROFILE\.claude\hooks\"
Copy-Item hooks\scan-content.js,hooks\shellter-trust.js "$env:USERPROFILE\.claude\hooks\"
node merge-settings.js "$env:USERPROFILE\.claude\settings.json"
```

`merge-settings.js` writes paths with forward slashes (e.g. `C:/Users/you/...`), which Node-on-Windows accepts in JSON.

## Hook Protocol

Hooks receive JSON on stdin and output JSON on stdout.

### Input (stdin)

```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "git status && npm test"
  }
}
```

### Output (stdout)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Auto-approved by hook"
  }
}
```

`permissionDecision` values:
- `"allow"`: auto-approve, no prompt shown
- `"deny"`: block the operation, reason shown to Claude
- `"ask"`: force the interactive prompt even if otherwise auto-allowed (used for high-risk untrusted scripts)

Exit codes:
- `0`: structured decision (or fallthrough if no output)
- `2`: hard block (stderr shown to user)

## Recursive Wrapper Checking

These wrappers used to be common bypass vectors. Both hooks now look inside them:

| Wrapper                      | Behaviour                                                  |
| ---------------------------- | ---------------------------------------------------------- |
| `bash -c '...'` / `sh -c`    | Inner command parsed; deny/approve recurses on each segment |
| `bash -c "$(curl ...)"`        | **Denied**, opaque payload (contains `$(`/backtick/`$VAR`) |
| `find … -exec CMD … \;`      | `CMD` is parsed and recursively checked                     |
| `xargs … CMD`                | `CMD` is parsed and recursively checked                     |
| `<(…)` / `>(…)`              | Inner command is recursively checked; `bash <(curl …)` and `source <(curl …)` are denied wholesale |

## Script trust store

The command line `bash install.sh` tells you nothing about what `install.sh`
*does*. shellter reads the file (first 256 KB) and scans its contents. If they
look high-risk (download-piped-to-shell, reverse shell, encoded-then-executed,
LOLBins) and the script isn't trusted, the hook returns **`ask`** with a message
naming the matched pattern and line and telling you to **open and read the script
yourself** before approving. It re-asks every run until you trust it.

Two ways to make it stop asking for a script you've reviewed:

1. **Native button** — pick **"Yes, don't ask again"** at the prompt. shellter
   honors the resulting `Bash(...)` / `PowerShell(...)` allow-rule from your
   project or user settings on subsequent runs.
2. **Trust CLI** — record the script's content hash:

   ```bash
   node ~/.claude/hooks/shellter-trust.js add ./install.sh   # trust it
   node ~/.claude/hooks/shellter-trust.js list               # show trusted
   node ~/.claude/hooks/shellter-trust.js remove <hash|path> # revoke
   ```

Trust is keyed by content hash, so a trusted script stays trusted if moved or
renamed, but **editing it invalidates trust and re-flags it**. The store lives at
`~/.claude/shellter-trust.json` (override with `SHELLTER_TRUST_FILE`). Clean
scripts are never flagged; only high-confidence malicious shapes trigger `ask`
(lower-confidence signals are audit-only), so ordinary build/install scripts pass
through untouched.

`ask`-reason display for hook-forced prompts is undocumented in Claude Code; if a
build doesn't surface it, flip `SCRIPT_RISK_DECISION` in `check-bash.js` from
`'ask'` to `'deny'` (the message reads correctly either way).

## Audit Log

Set `CLAUDE_HOOK_LOG=/path/to/log.jsonl` to record one JSON line per decision (timestamp, hook, tool, decision, reason, snippet). **Disabled by default**. If `CLAUDE_HOOK_LOG` is unset *or empty* (e.g. `CLAUDE_HOOK_LOG=`), no log file is written. There is no OS-specific default path; you must opt in by setting the variable to a non-empty path. Fail-silent on write errors. (Note: a value that's only whitespace, like `" "`, is truthy and *will* try to write to a file with that literal name, so avoid that.)

Set `CLAUDE_HOOK_DEBUG=1` to mirror the same lines to stderr so they show up in Claude Code's hook output panel.

Linux / macOS:
```bash
CLAUDE_HOOK_LOG=/tmp/hook.log claude  # or run the hooks manually
tail -f /tmp/hook.log                 # to see every decision live
```

Windows (PowerShell): use a native path with backslashes, or forward slashes work too. Avoid `/tmp/...` (it's not a real path on Windows). The directory must already exist; the hook fails silently if it can't write.
```powershell
$env:CLAUDE_HOOK_LOG = "$env:TEMP\hook.log"   # safest, %TEMP% always exists per-user
# or a fixed path you control (must mkdir first):
$env:CLAUDE_HOOK_LOG = 'c:\temp\hook.log'     # single quotes keep \ literal
$env:CLAUDE_HOOK_LOG = "c:\temp\hook.log"     # double quotes also fine in PS (\ is not an escape)
claude
Get-Content $env:CLAUDE_HOOK_LOG -Wait        # tail -f equivalent
```

Windows (cmd.exe):
```cmd
set CLAUDE_HOOK_LOG=%TEMP%\hook.log
:: or:
set CLAUDE_HOOK_LOG=c:\temp\hook.log
claude
```

Forward slashes (`c:/temp/hook.log`) also work everywhere on Windows; Node normalizes them. Useful inside `settings.json` to avoid escaping `\\`.

## Adding Custom Patterns

### New deny pattern in `check-bash.js`

Add to the `DENY_PATTERNS` array:

```js
[/your-regex-here/i, 'Reason shown when blocked'],
```

### New approve pattern in `check-bash.js`

Add to `APPROVE_PATTERNS`. Anchor with `^\s*` so it only matches at the start of a segment:

```js
/^\s*your-command-pattern\b/,
```

### New sensitive file pattern in `check-sensitive-files.js`

Add to one of the existing path regexes (`SENSITIVE_FILES`, `SENSITIVE_DIRS`, etc.) or define a new one and check it inside `pathMatchesAnySensitive`.

## Project-Specific Overrides

Create `<project>/.claude/settings.local.json` to add project-specific permissions:

```json
{
  "permissions": {
    "allow": [
      "Bash(cargo test:*)",
      "Bash(npm run:*)",
      "Bash(uv run:*)"
    ]
  }
}
```

These permissions auto-allow specific Bash patterns without going through the hook.

## Threat Model

The hooks are a **defense-in-depth layer**, not a sandbox. They protect against:
- Accidental or LLM-mediated execution of well-known dangerous commands
- Reading well-known sensitive paths (incl. via symlink)
- Writing files with prompt-injection / fake-tool-call payloads
- Common bypass wrappers (`bash -c`, `find -exec`, `xargs`, process substitution)
- Steganographic prompt injection via invisible Unicode

They do **not** protect against:
- Time-of-check / time-of-use races (an attacker can swap a symlink between the realpath check and the actual read)
- Kernel-level attacks or processes already running as you
- Anything Claude can do via tools other than Bash/Read/Write/Edit/Glob/Grep
- Brand-new attack patterns not yet in the deny list, so keep the list updated

### Compound shapes that auto-approve

A compound command (e.g. `cmd1 && cmd2`, `cmd1 ; cmd2 | cmd3`) auto-approves only when **every** subcommand independently matches an APPROVE pattern. Env-var prefixes (`FOO=bar cmd`, `export FOO=bar && cmd`) are stripped before matching, so `pnpm -w test` and `export NODE_OPTIONS=--use-system-ca && pnpm -w test` both go through.

Heredoc / here-string invocations (`python|python2|python3 << ['"]?MARKER['"]?` and `cat|tee REDIR << MARKER`) are scanned separately. A Python heredoc auto-approves only when the body has no `import` of `subprocess` / `socket` / `urllib` / `requests` / `shutil` / `ctypes` / `paramiko` / `importlib`, no `os.system|popen|exec*|fork|kill|remove|unlink|chmod|chown|setuid`, no `eval|exec|__import__|compile|getattr`, and every `open()` call uses a literal relative path that is not absolute / not `..`-traversing / not a sensitive file. `cat`/`tee` heredocs auto-approve when the redirect target is a safe relative path; the body itself is treated as opaque data.

If a shape isn't covered here, you'll get the standard Claude Code prompt. Pick **"Yes, don't ask again"** to persist that allow rule to the current project's `.claude/settings.local.json`, or **"Allow this time"** to allow only for the current session.

## Troubleshooting

**Hook not firing**: Check that `~/.claude/settings.json` has the `hooks` key and paths are absolute and correct for your OS.

**False positive on a deny**: Set `CLAUDE_HOOK_LOG` to a writable path (Unix: `/tmp/hook.log`; Windows PowerShell: `$env:CLAUDE_HOOK_LOG = "$env:TEMP\hook.log"`), reproduce the issue, then check the log for the matched reason. Adjust the regex (or add a project-specific allow rule).

**Hook crashes / no output**: Hooks that exit non-zero (except 2) or produce no output fall through to the normal permission prompt. `CLAUDE_HOOK_DEBUG=1` mirrors decisions to stderr.

**Testing a hook manually**:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | node ~/.claude/hooks/check-bash.js
```

**Running the test suite**:
```bash
node test-hooks.js
```

## Changelog

Current version is 0.3.0 (script-content scanning, trust store, hardened
injection detection). The full history lives in [CHANGELOG.md](CHANGELOG.md).
