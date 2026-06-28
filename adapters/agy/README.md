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

Put shellter's `hooks/` somewhere stable, then register a `PreToolUse` hook —
workspace `.agents/hooks.json`, a `hooks` block in the CLI settings
(`~/.gemini/antigravity-cli/settings.json`), or a plugin (`agy plugin`):

```json
{
  "PreToolUse": [
    {
      "matcher": "run_command|run_shell_command|write_to_file|replace_file_content|multi_replace_file_content",
      "hooks": [
        { "type": "command", "command": "node \"F:/opt/projs/ai/claude/shellter/adapters/shared/shellter-host-hook.js\" --host=agy", "timeout": 30 }
      ]
    }
  ]
}
```

Set `SHELLTER_HOOKS_DIR` in the hook's environment if `hooks/` isn't at the
`../../hooks` dev location relative to the shim.

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
