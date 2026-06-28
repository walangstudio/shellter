# shellter — pi adapter

Gates [pi](https://pi.dev) (`@earendil-works/pi-coding-agent`) agent tool calls
through shellter's existing hooks — the same detector shellter uses for Claude
Code. Dangerous Bash/PowerShell, sensitive-file reads, and prompt injection are
blocked in pi too.

## How it works

`shellter.ts` is a pi extension. On the `tool_call` event it reshapes the call
into shellter's stdin JSON, runs `check-bash.js` / `check-sensitive-files.js`
(one shared detector — no duplicated rules), and returns `{ block: true, reason }`
when the decision is `deny` or `ask`. The reason (including the "this protects
the user, don't bypass" notice) is surfaced to the model.

Only `tool_call` (the agent's own tools) is gated — that is the prompt-injection
threat model. `user_bash` (you typing `!cmd`) is explicit human intent, not an
injection vector, and pi exposes no block flag for it, so it is left alone.

Covered tools: `bash`, `read`, `write`, `edit`, `grep`, `find`. Unknown/custom/MCP
tools fall through (their input shape isn't known to map safely).

## Install

1. Copy `shellter.ts` to `~/.pi/agent/extensions/shellter.ts` (the global
   extensions dir — always loaded, not repo-controlled).
2. Put shellter's `hooks/` next to it as `~/.pi/agent/extensions/shellter-hooks/`
   (or set `SHELLTER_HOOKS_DIR` to an existing shellter `hooks/` directory).
3. Restart pi (or `/reload`).

`node` runs the hooks if present, otherwise the pi runtime (bun). Set
`SHELLTER_DEBUG=1` to log every decision to `shellter-debug.log` next to the
extension.

## Verify

`bun adapters/pi/test-adapter.ts` captures the `tool_call` handler, drives it
with crafted events, and asserts the dangerous ones are blocked and the safe
ones pass (spawns the real hooks). 11/11 expected.

## Status

The extension API (`tool_call` → `{ block, reason }`) is verified against the
installed pi 0.80.2 type definitions; the adapter is tested deterministically.
Live end-to-end in a real pi session is the recommended final check.
