# shellter — codex adapter (OpenAI Codex CLI)

Gates [Codex CLI](https://developers.openai.com/codex) shell commands through
shellter's existing hooks — the same detector shellter uses for Claude Code.
Requires **Codex ≥ v0.124.0** (the hooks engine; verify with `codex --version`).

## How it works

Codex's `PreToolUse` hook runs an external program before a tool executes, hands
it the call as JSON on stdin, and blocks on `permissionDecision:"deny"` (or exit 2).
That contract is nearly identical to Claude Code's. The shared shim
`../shared/shellter-host-hook.js --host=codex` normalizes Codex's payload into
shellter's stdin JSON, runs `check-bash.js` / `check-sensitive-files.js`, and
emits Codex's deny verdict.

`ask` (shellter's Tier-2 dev-workflow guards: `git push`, `sudo`, `DROP`, …) is
**not** emitted as a hook verdict — Codex's `PreToolUse` only acts on `deny`, so
shellter stays silent and lets Codex's own approval prompt handle those (its
native gate already asks for risky commands). Tier-1 threats are hard-denied.

## Install

Put shellter's `hooks/` somewhere stable, then add to `~/.codex/config.toml`
(use the absolute path to this repo's shim and forward slashes on Windows):

```toml
[[hooks.PreToolUse]]
matcher = ".*"                 # route every tool through the shim; it self-filters to shell/file tools.
                              # Do NOT narrow this unless you know Codex's exact tool names on your
                              # platform -- a too-narrow matcher silently skips the shim for unlisted tools.
[[hooks.PreToolUse.hooks]]
type = "command"
command = 'node "F:/opt/projs/ai/claude/shellter/adapters/shared/shellter-host-hook.js" --host=codex'
timeout = 30
statusMessage = "shellter checking command"
```

If you keep `hooks/` outside the repo, set `SHELLTER_HOOKS_DIR` in the hook's
environment instead of relying on the `../../hooks` dev fallback.

Codex shows a one-time trust prompt for a new command hook (per hook-hash) before
it runs — approve it once. Only managed/MDM config bypasses that.

## Ceiling (be aware)

- Codex reliably intercepts **simple** shell calls only; complex/wrapped
  invocations may not reach the hook (OpenAI's own caveat).
- `apply_patch` (file-edit) interception is unreliable, so shellter's file-write /
  injection protection on Codex is **best-effort**, weaker than on Claude
  Code/opencode/pi. Codex's native `sandbox_mode` + protected `.git`/`.codex`
  paths partially compensate.
- Below v0.124.0 the hook doesn't exist; fall back to static
  `decision="forbidden"` `prefix_rule`s in `~/.codex/rules/` for the catastrophic
  set, or a PATH-shim wrapper.

## Verify

`node adapters/shared/test-host-hook.js` drives the shim with Codex-format JSON
and asserts the translated verdict (spawns the real hooks). Live: configure the
hook above and run a Codex command that should be denied.
