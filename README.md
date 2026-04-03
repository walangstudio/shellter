# Claude Code Security Hooks

Global PreToolUse hooks that auto-allow safe operations and block dangerous ones across all Claude Code sessions.

## What It Does

Two Node.js hooks run before every tool call:

**check-bash.js** gates all Bash commands:
- Splits chained commands (&&, ||, ;) and checks each segment
- DENY: reverse shells, data exfiltration, encoded payloads, privilege escalation, git force push, rm system dirs, persistence mechanisms, container escapes, etc.
- APPROVE: read-only git, safe git writes, ls/pwd/which, version checks, cargo/npm build/test
- Everything else: falls through to the normal Claude Code permission prompt

**check-sensitive-files.js** gates Read, Write, Edit, Glob, Grep:
- Blocks access to .env, .pem, .key, .crt, .ssh/, .aws/, .gnupg/ and similar
- Detects prompt injection in written content (role hijacking, instruction overrides)
- Detects encoded eval/exec patterns and polyglot attacks in data files
- Blocks grep patterns that extract secret values

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

No other dependencies -- hooks use only Node.js built-ins (no jq, no grep, no bash required).

### Linux

```bash
# 1. Copy hook scripts
mkdir -p ~/.claude/hooks
cp hooks/check-bash.js ~/.claude/hooks/
cp hooks/check-sensitive-files.js ~/.claude/hooks/

# 2. Merge into existing settings (safe to run multiple times)
#    Adds "permissions" and "hooks" keys, keeps everything else intact.
#    Automatically fixes paths to match your home directory.
node merge-settings.js

# Or if you have NO existing settings.json and want a clean start:
# cp settings-template.json ~/.claude/settings.json
# sed -i "s|/home/nino|$HOME|g" ~/.claude/settings.json
```

### macOS

```bash
# 1. Copy hook scripts
mkdir -p ~/.claude/hooks
cp hooks/check-bash.js ~/.claude/hooks/
cp hooks/check-sensitive-files.js ~/.claude/hooks/

# 2. Merge into existing settings
node merge-settings.js

# Or clean start:
# cp settings-template.json ~/.claude/settings.json
# sed -i '' "s|/home/nino|$HOME|g" ~/.claude/settings.json
```

### Windows

Claude Code on Windows runs hooks via Node.js, so .js hooks work natively.

```powershell
# 1. Copy hook scripts
mkdir -Force "$env:USERPROFILE\.claude\hooks"
Copy-Item hooks\check-bash.js "$env:USERPROFILE\.claude\hooks\"
Copy-Item hooks\check-sensitive-files.js "$env:USERPROFILE\.claude\hooks\"

# 2. Merge into existing settings
node merge-settings.js "$env:USERPROFILE\.claude\settings.json"

# Or clean start:
# Copy-Item settings-template.json "$env:USERPROFILE\.claude\settings.json"
# Then manually update paths (see below)
```

Windows paths in settings.json can use forward slashes (`C:/Users/...`) which Node.js handles fine. The merge script handles path conversion automatically.

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
- `"allow"` -- auto-approve, no prompt shown
- `"deny"` -- block the operation, reason shown to Claude
- `"ask"` -- force the interactive prompt even if otherwise auto-allowed

Exit codes:
- `0` -- structured decision (or fallthrough if no output)
- `2` -- hard block (stderr shown to user)

## Adding Custom Patterns

### New deny pattern in check-bash.js

Add to the `DENY_PATTERNS` array:

```javascript
[/your-regex-here/i, 'Reason shown when blocked'],
```

### New approve pattern in check-bash.js

Add to the `APPROVE_PATTERNS` array:

```javascript
/^\s*your-command-pattern\b/,
```

Approve patterns should be anchored to `^\s*` to match the start of a command segment.

### New sensitive file pattern in check-sensitive-files.js

Add a regex constant and check it in the sensitive file section:

```javascript
const MY_PATTERN = /my-pattern/i;
// ...
if (MY_PATTERN.test(filePath)) {
  deny('My custom reason');
}
```

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

These permissions auto-allow specific Bash patterns without going through the hook. Use for trusted project-specific commands.

## Troubleshooting

**Hook not firing**: Check that `~/.claude/settings.json` has the `hooks` key and paths are absolute and correct for your OS.

**False positive on a deny**: Check which pattern matched by adding `console.error('Matched:', reason);` before the deny call in the hook script. Then adjust the regex.

**Polyglot false positive on .md files**: This was fixed -- .md files are excluded from polyglot detection. If you see it on other file types, the content genuinely contains shell substitution syntax in a data file.

**Hook crashes / no output**: Hooks that exit non-zero (except 2) or produce no output fall through to the normal permission prompt. Check stderr for errors.

**Testing a hook manually**:
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | node ~/.claude/hooks/check-bash.js
```
