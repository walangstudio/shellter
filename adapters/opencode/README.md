# shellter — opencode adapter (experimental)

Gates [opencode](https://opencode.ai) tool calls through shellter's existing hooks —
the same detector shellter uses for Claude Code. Dangerous Bash/PowerShell,
sensitive-file reads, and prompt injection are blocked in opencode too.

## How it works

`shellter.ts` is an opencode plugin. On `tool.execute.before` it reshapes the call
into shellter's stdin JSON, runs `check-bash.js` / `check-sensitive-files.js` (one
shared detector — no duplicated rules), and throws to block when the decision is
`deny` or `ask`. The block reason (including the "this protects the user, don't
bypass" notice) is surfaced to the model.

## Install

1. Copy `shellter.ts` to `~/.config/opencode/plugin/shellter.ts`.
2. Put shellter's `hooks/` next to it as `~/.config/opencode/shellter-hooks/`
   (or set `SHELLTER_HOOKS_DIR` to an existing shellter `hooks/` directory).
3. Restart opencode.

`node` is used to run the hooks if present, otherwise the opencode runtime (bun).
Set `SHELLTER_DEBUG=1` to log every decision to `shellter-debug.log` next to the
plugin.

## Verify

`bun adapters/opencode/test-adapter.ts` drives `tool.execute.before` with crafted
calls and asserts the dangerous ones are blocked and the safe ones pass (spawns the
real hooks).

## Status

Experimental. Verified live to block sensitive-file reads (`Read .env`,
`Get-Content .env`) and copy-to-benign-name exfil (`Copy-Item .env …`) in a real
opencode session. pi and codex adapters, and an opt-in passthrough LLM judge for the
gray zone, are planned.
