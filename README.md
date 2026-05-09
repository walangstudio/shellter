# Claude Code Security Hooks

Global PreToolUse hooks that auto-allow safe operations and block dangerous ones across all Claude Code sessions.

## What It Does

Two Node.js hooks run before every tool call:

**check-bash.js** gates all Bash commands:
- Splits chained commands (`&&`, `||`, `;`) and checks each segment
- Recursively descends into `bash -c '...'`, `sh -c '...'`, `find -exec`, `xargs`, and `<(...)` / `>(...)` process substitutions, so wrappers can't hide a payload
- Strips invisible/steganographic Unicode (zero-widths, bidi overrides, tag chars) before matching
- DENY: reverse shells, exfiltration, encoded payloads, privilege escalation, identity backdoors via `git config`, persistence (shell rc / `.git/hooks/` / CI configs), kernel module load, loader injection (`LD_PRELOAD`), crypto miners, container escape, force-push to main, `rm -rf` of system dirs, and more
- APPROVE: read-only git plus `pull` / `merge` / `rebase` / `switch` / `blame` / `reflog`; `gh` read-only; `go` / `kubectl get|describe|logs` / `terraform plan|validate` / `helm lint|template`; `ruff` / `black` / `mypy` / `tsc` / `eslint` / `prettier` / `vitest` / `jest`; `pnpm` / `bun` build/test; `pre-commit` / `shellcheck` / `hadolint` / `yamllint`; standard read-only Unix tools
- Mixed/unknown: falls through to the normal Claude Code permission prompt

**check-sensitive-files.js** gates Read, Write, Edit, Glob, Grep:
- Resolves symlinks before checking — `ln -s ~/.env /tmp/x; Read /tmp/x` is blocked
- Blocks access to `.env*`, `.pem`, `.key`, `.crt`, `.p12`, `.pfx`, `.ssh/`, `.gnupg/`, `.aws/`, `.azure/`, `.kube/`, plus their `.bak` / `.old` / `.backup` variants
- Blocks read of credential files: `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.cargo/credentials`, `.docker/config.json`, `.config/gh/hosts.yml`, `.ssh/config`
- Blocks wallet / keystore / browser-cookie databases
- Detects prompt-injection in written content: instruction-override phrases, role hijacking ("pretend you are", "assume the role of", "from now on you are"), jailbreak ("DAN mode", "developer mode"), role-tag injection (`<|im_start|>system`, `[SYSTEM]`, `[INST]`)
- Detects fake tool-call tags (`<function_calls>`, `<invoke>`) in written content
- Detects steganographic injection: invisible Unicode characters in source files
- Detects encoded eval/exec, polyglot shell substitution in data files (incl. `.json.bak` / `.yaml.old`), markdown `javascript:` / `data:text/html` URLs, and ANSI-escape sequences in source files
- Blocks grep patterns that extract literal secret values or known token shapes (AWS access keys, GitHub tokens, Slack tokens, JWTs, Bearer tokens)

## File Layout

```
~/.claude/
  settings.json           # hooks registration + global permissions
  hooks/
    check-bash.js         # bash command gatekeeper
    check-sensitive-files.js  # file access gatekeeper
```

Project-specific overrides go in `<project>/.claude/settings.local.json`.

## Installation

### Prerequisites

Node.js >= 18 (Claude Code requires Node.js 18+, so it's already installed if you have Claude Code).

No other dependencies — hooks use only Node.js built-ins.

### Linux / macOS

```bash
# 1. Copy hook scripts
mkdir -p ~/.claude/hooks
cp hooks/check-bash.js ~/.claude/hooks/
cp hooks/check-sensitive-files.js ~/.claude/hooks/

# 2. Merge into existing settings (safe to run multiple times).
#    Substitutes __HOME__ -> $HOME, prints the sha256 of each installed hook.
node merge-settings.js
```

### Windows

```powershell
mkdir -Force "$env:USERPROFILE\.claude\hooks"
Copy-Item hooks\check-bash.js "$env:USERPROFILE\.claude\hooks\"
Copy-Item hooks\check-sensitive-files.js "$env:USERPROFILE\.claude\hooks\"
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
- `"allow"` — auto-approve, no prompt shown
- `"deny"` — block the operation, reason shown to Claude
- `"ask"` — force the interactive prompt even if otherwise auto-allowed

Exit codes:
- `0` — structured decision (or fallthrough if no output)
- `2` — hard block (stderr shown to user)

## Recursive Wrapper Checking

These wrappers used to be common bypass vectors. Both hooks now look inside them:

| Wrapper                      | Behaviour                                                  |
| ---------------------------- | ---------------------------------------------------------- |
| `bash -c '...'` / `sh -c`    | Inner command parsed; deny/approve recurses on each segment |
| `bash -c "$(curl …)"`        | **Denied** — opaque payload (contains `$(`/backtick/`$VAR`) |
| `find … -exec CMD … \;`      | `CMD` is parsed and recursively checked                     |
| `xargs … CMD`                | `CMD` is parsed and recursively checked                     |
| `<(…)` / `>(…)`              | Inner command is recursively checked; `bash <(curl …)` and `source <(curl …)` are denied wholesale |

## Audit Log

Set `CLAUDE_HOOK_LOG=/path/to/log.jsonl` to record one JSON line per decision (timestamp, hook, tool, decision, reason, snippet). **Disabled by default** — if `CLAUDE_HOOK_LOG` is unset *or empty* (e.g. `CLAUDE_HOOK_LOG=`), no log file is written. There is no OS-specific default path; you must opt in by setting the variable to a non-empty path. Fail-silent on write errors. (Note: a value that's only whitespace, like `" "`, is truthy and *will* try to write to a file with that literal name — avoid.)

Set `CLAUDE_HOOK_DEBUG=1` to mirror the same lines to stderr so they show up in Claude Code's hook output panel.

Linux / macOS:
```bash
CLAUDE_HOOK_LOG=/tmp/hook.log claude  # or run the hooks manually
tail -f /tmp/hook.log                 # to see every decision live
```

Windows (PowerShell) — use a native path with backslashes, or forward slashes work too. Avoid `/tmp/...` (it's not a real path on Windows). The directory must already exist; the hook fails silently if it can't write.
```powershell
$env:CLAUDE_HOOK_LOG = "$env:TEMP\hook.log"   # safest — %TEMP% always exists per-user
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

Forward slashes (`c:/temp/hook.log`) also work everywhere on Windows — Node normalizes them. Useful inside `settings.json` to avoid escaping `\\`.

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
- Brand-new attack patterns not yet in the deny list — keep the list updated

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

### v2 — security hardening + reduced prompts
- Recursive checking of `bash -c`, `sh -c`, `find -exec`, `xargs`, and `<(…) / >(…)` process substitution
- Symlink resolution in file checks (`safeRealpath`)
- Unicode invisible-character normalization in command input + steganography detection in written content
- New deny categories: identity/git backdoor (`git config core.hooksPath` etc.), shell-rc and CI-config writes, kernel module load, loader injection, crypto miners, alternative scheduling (`at`/`batch`/`systemd-run`), debugger attach
- New approve categories: `git pull|merge|rebase|switch|blame|reflog`, `gh` read-only, `go`, `kubectl get|describe|logs`, `terraform plan|validate`, `helm lint|template`, Python/JS/TS linters and formatters, `pnpm`/`bun` build/test, `pre-commit`
- New sensitive-file coverage: `.gitconfig`, `.git-credentials`, `.npmrc`, `.pypirc`, `.cargo/credentials`, `.docker/config.json`, `.config/gh/hosts.yml`, `.ssh/config`, wallets, browser cookie DBs; backup forms (`.env.bak`, `.key.old`, `.json.bak`)
- New prompt-injection coverage: jailbreak phrases, role-tag injection (`<|im_start|>`, `[SYSTEM]`), fake tool-call tags (`<function_calls>`, `<invoke>`), markdown `javascript:` URLs, ANSI escape sequences
- Token-shape grep blocking (AWS, GitHub, Slack, JWT, Bearer)
- Opt-in audit log via `CLAUDE_HOOK_LOG` and `CLAUDE_HOOK_DEBUG`
- Settings template uses `__HOME__` placeholder (no more user-specific path)
- Test suite expanded from 57 to 164+ cases including bypass regressions and a real symlink fixture
