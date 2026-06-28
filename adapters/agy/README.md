# shellter — agy adapter (Antigravity CLI)

Gates [Antigravity](https://antigravity.google) (`agy`, Google's Gemini-CLI
replacement) tool calls through shellter's existing hooks — the same detector
shellter uses for Claude Code. Verified against agy 1.0.12.

## How it works

Antigravity's `PreToolUse` hook runs an external program before a tool executes,
hands it the call as JSON on stdin, and blocks on `{"decision":"deny"}` (or a
non-zero exit). The shared shim `../shared/shellter-host-hook.js --host=agy`
normalizes agy's payload into shellter's stdin JSON, runs `check-bash.js` /
`check-sensitive-files.js`, and emits agy's verdict. Unlike Codex, agy honors
`deny`, `ask`, **and** `allow`, so shellter's Tier-2 guards surface as `ask`.

## Install

> Antigravity is new and its hook config keys/paths have drifted between builds.
> The mechanism below is correct; **verify the exact spelling against your build**
> (`agy help`, the in-app `/hooks` command, and antigravity.google/docs/hooks)
> before relying on it.

Put shellter's `hooks/` somewhere stable, then register a `PreToolUse` hook in a
`hooks.json`. Verified locations for **agy 1.0.12** (the `hooks` key does **not**
exist in `settings.json` on this build — don't use it):

- **Per-directory:** `<workspace>/.agents/hooks.json`
- **Global (all workspaces):** `~/.gemini/config/hooks.json`

The top-level key is a user-chosen hook name. Use matcher `"*"` so every tool
(shell, file read, and write) is routed — a narrow matcher silently skips tools
it doesn't list, which is how a native `view_file` read of `.env` slips through:

```json
{
  "shellter": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "node \"F:/opt/projs/ai/claude/shellter/adapters/shared/shellter-host-hook.js\" --host=agy", "timeout": 30 }
        ]
      }
    ]
  }
}
```

Set `SHELLTER_HOOKS_DIR` in the hook's environment if `hooks/` isn't at the
`../../hooks` dev location relative to the shim.

> **Hooks load lazily.** agy loads `hooks.json` when you send your **first
> message** in a session, not at startup — so `/hooks` looks empty until you've
> prompted once. This is not a gap: a tool only runs after a message, so the hook
> is always armed before any command executes. Verify by behavior (try to read
> `.env`), not by `/hooks`. On Windows, `/hooks`'s own editor writes to the wrong
> path ([issue #49](https://github.com/google-antigravity/antigravity-cli/issues/49)) —
> edit the `hooks.json` file directly instead.

The shim is host-agnostic and field-defensive (reads tool name/args from several
plausible paths), so minor key drift in agy's payload is absorbed.

## Ceiling (be aware)

- A hook only covers tools you list in `matcher`. The agent's built-in **browser**
  surface and arbitrary MCP tools are separate — enumerate any MCP tool names you
  want gated. agy also has a native OS sandbox (`--sandbox`) orthogonal to shellter.
- The static `permissions.allow/deny` lists (exact/glob/regex) are a weaker
  complementary layer for fast hard blocks; shellter's value is the dynamic hook.

## Verify

`node adapters/shared/test-host-hook.js` drives the shim with agy-format JSON
(`toolCall.{name,args}`) and asserts the translated `decision` (spawns the real
hooks). Live: register the hook and run an `agy` command that should be denied.
