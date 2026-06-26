# Changelog

What changed, and when. Versions follow [semver](https://semver.org). While we
are pre-1.0, a minor bump (0.x.0) is where the interesting changes land: new deny
rules, new approves, new platforms.

Nothing was versioned before now, so 0.1.0 is the state the hooks were already in
when we started counting. Everything in this session is 0.2.0.

## [0.5.0] - 2026-06-27

Secret-exfiltration hardening across every shell, an anti-bypass notice that stops
an AI agent from routing around a block, and an experimental opencode adapter.

### Added
- **Sensitive-file reads blocked in PowerShell and cmd, not just bash.** The bash
  `cat .env` rule had no PowerShell/cmd equivalent, so `Get-Content .env`,
  `gc ~/.ssh/id_rsa`, `type .env`, `findstr ... .env`, `Format-Hex key.pem`,
  `Select-String`, and `[IO.File]::ReadAllText(...)` of a secret all walked through.
  Now denied. (Found live: an opencode agent read `.env` via `Get-Content` after its
  `read` tool was blocked.)
- **Broadened the bash/zsh/fish/macOS reader list** beyond `cat`/`head` to the common
  dumpers — `xxd`, `od`, `strings`, `base64`, `dd`, `openssl`, `gpg`, `jq`, `cut`,
  `tr`, … — so a secret can't be dumped around the `cat` rule on any POSIX shell or
  macOS Terminal.
- **`$(<secret)` shell file-read substitution** is now caught.
- **Copy/move/rename exfil blocked.** Copying a secret to a benign name and reading
  the copy is the obvious next move; `Copy-Item`/`cp`/`mv`/`Rename-Item`/`robocopy`/
  `[IO.File]::Copy` of a sensitive source (or the whole `.ssh`/`.aws`/`.gnupg` dir)
  is denied.
- **Inline-interpreter reads** (`python -c`, `node -e`, `ruby -e`, `perl -e`, `php`)
  that reference a sensitive path are denied.
- **Anti-bypass notice on every block.** Each deny/ask reason now tells the agent the
  block protects the user and not to bypass, re-encode, copy, or rename around it —
  stop and tell the user. In practice this turns a task-focused model away from
  probing workarounds (verified live: the agent stopped and explained instead of
  copying `.env` to a non-dotfile name).
- **Experimental opencode adapter** (`adapters/opencode/`). An opencode plugin that
  routes `tool.execute.before` through shellter's existing hooks (one shared
  detector), so dangerous Bash/PowerShell, sensitive-file access, and prompt
  injection are gated in opencode too. Verified live (blocks `.env` reads + the
  `Copy-Item` evasion). pi/codex adapters and an opt-in passthrough LLM judge are
  planned.

### Notes
- Detection stays pattern + heuristic. A determined agent that runs arbitrary code (a
  custom `python`/`node` script, an obfuscated path) can still read a file — no
  command-pattern hook fully prevents that. The real boundary for "the agent must
  never see this secret" is not exposing it to the agent (sandbox / secret manager);
  shellter raises the bar against the casual and obvious paths.
- Test suite grew 329 -> 349. The bash path stays byte-compatible for pre-existing cases.

## [0.4.1] - 2026-06-26

Distribution moved to a shared marketplace, plus plugin-load and destructive-`rm`
fixes.

### Fixed
- **Plugin hooks now actually load.** `plugin.json` referenced
  `./hooks/hooks.json` in its `hooks` field, but Claude Code auto-loads the
  standard `hooks/hooks.json` — the reference loaded it a second time, so the
  plugin failed with "Duplicate hooks file detected: Hook load failed" and
  shellter's hooks never registered (the plugin installed but did nothing).
  Removed the redundant `hooks` field; the standard file auto-loads. `manifest.hooks`
  is only for *additional* hook files beyond the standard one.
- **`rm -rf /` and `rm -rf ~` are now blocked.** The system-directory and
  home-directory rm rules anchored the target with a trailing `\b`, which never
  matches at end of string after a non-word char (`/`, `~`). So bare
  `rm -rf /`, `rm -rf / --no-preserve-root`, and `rm -rf ~` slipped through to a
  normal permission prompt instead of being denied (named targets like `/etc`,
  `/usr`, `/home`, `/*` were always caught). Both anchors are corrected; the
  PowerShell rules already anchored with `(\s|$|\*)` and were unaffected.

### Changed
- **Marketplace moved to `walangstudio/marketplace`.** shellter no longer
  self-hosts a marketplace (`.claude-plugin/marketplace.json` is removed from this
  repo). It's now one plugin in the Walang Studio catalog, alongside future
  projects. The install path changes to:
  ```
  /plugin marketplace add walangstudio/marketplace
  /plugin install shellter@walangstudio
  ```
  If you added the old `walangstudio/shellter` marketplace, remove it with
  `/plugin marketplace remove shellter`, then add `walangstudio/marketplace`.

### Notes
- The plugin's distribution catalog moved to its own repo; the only hook-logic
  change is the `rm` deny-rule fix above. Test suite grew 324 → 329.

## [0.4.0] - 2026-06-26

Distribution. shellter is now a Claude Code plugin with its own marketplace, so
installing it is two commands instead of copy-the-scripts-and-merge-settings.

### Added
- **Claude Code plugin + marketplace.** The repo is both a marketplace
  (`.claude-plugin/marketplace.json`) and the plugin (`.claude-plugin/plugin.json`
  + `hooks/hooks.json`). Install with:
  ```
  /plugin marketplace add walangstudio/shellter
  /plugin install shellter@shellter
  ```
  The PreToolUse hooks (Bash/PowerShell gating + Read/Write/Edit/Glob/Grep
  protection) register automatically via `${CLAUDE_PLUGIN_ROOT}`, with a
  `commandWindows` variant so it works on Windows too. No `merge-settings.js`,
  no hand-editing `settings.json`.

### Notes
- The manual install (`merge-settings.js` + copying hooks) still works and is the
  path for non-plugin clients. If you switch to the plugin, remove the manual
  hooks from `~/.claude/settings.json` so they don't double-fire.
- Plugin hooks are additive with your own settings hooks and use the same
  `permissionDecision` protocol; the most restrictive decision wins.
- No hook-logic changes from 0.3.0 — this release is packaging only.

## [0.3.0] - 2026-06-26

Until now the hooks judged a command by its text alone. `bash install.sh` told
them nothing about what `install.sh` actually does, so a script whose body was
`curl … | sh` walked straight through. This release reads the script.

### Added
- **Script-content scanning.** When a command executes a local script
  (`bash`/`sh`/`zsh`/`dash`/`ash`/`ksh`/`fish X`, `./X`, `source X` / `. X`,
  `powershell`/`pwsh -File X`, `& ./X.ps1`), `check-bash.js` resolves the path
  against the call's `cwd`, reads the first 256 KB, and scans the contents for
  download-pipe-to-shell, `/dev/tcp` reverse shells, base64/xxd decode-then-exec,
  `-EncodedCommand` / `IEX` / `.DownloadString(`, AMSI bypass, and LOLBins
  (`certutil`/`bitsadmin`/`mshta`/`regsvr32`). High-risk + untrusted returns
  `ask` with a message naming the pattern, file, and line, and telling you to
  open and read the script yourself. I/O happens only when a script-exec shape
  matches, so the hot path is untouched.
- **Content-hash trust store** (`~/.claude/shellter-trust.json`, override with
  `SHELLTER_TRUST_FILE`) plus a `shellter-trust.js` CLI (`add` / `list` /
  `remove`). Trust is keyed by the hash of the scanned window, so a trusted
  script survives moves/renames but re-flags after an edit.
- **Native allow-rule honoring.** A `Bash(...)` / `PowerShell(...)` allow-rule
  from your project/user settings (e.g. from picking "Yes, don't ask again")
  also silences a script flag. Match is conservative (exact or `:*` prefix).
- **`scan-content.js`**, a shared zero-dependency scanner with a severity model
  (only `high` drives a decision; `medium`/`low` are advisory).
- **Hardened prompt-injection detection** in written content: variation-selector
  smuggling (U+FE00–FE0F / U+E0100–E01EF), a recursive invisible-strip that
  survives interleaved-surrogate re-forming, homoglyph / mixed-script tokens,
  broadened role markers (ChatML / Llama / Mistral, line-start fake transcripts),
  Policy-Puppetry config tags, MCP tool-poisoning `<IMPORTANT>` blocks,
  override-phrase + exfil-target co-occurrence, and a bounded base64/hex
  decode-one-layer-then-rescan.

### Changed
- `source X` / `. X` is no longer blanket auto-approved. It now routes through
  the script scanner: clean is allowed (unchanged behavior), dangerous + untrusted
  asks, trusted is allowed.

### Notes
- New decision: `check-bash.js` can now return `ask` (it previously only emitted
  `allow`/`deny`). Selectable via the `SCRIPT_RISK_DECISION` constant — flip to
  `'deny'` if a Claude Code build doesn't surface `ask` reasons.
- Detection is pattern + heuristic, pure JS, zero new dependencies. No offline,
  no-runtime ML detector is light enough to vendor into a sub-100ms hook;
  heuristics raise attacker cost and catch the known shapes, they are not
  complete (base32, novel framings, and multi-turn attacks can still evade).
- Test suite grew from 282 to 324 cases. The bash path stays byte-compatible for
  every pre-existing case.

## [0.2.0] - 2026-05-24

The cross-platform release. Until now the hooks only really understood Unix
bash. PowerShell commands were waved through with bash-shaped rules, which is
about as useful as a screen door on a submarine.

### Added
- PowerShell support. `check-bash.js` now branches on `tool_name`: bash keeps its
  Unix and macOS parsing, PowerShell gets a PowerShell-aware splitter (backtick is
  an escape char, not command substitution) and its own deny and approve sets.
- PowerShell deny rules: `Remove-Item -Recurse -Force` of home/root/wildcard,
  `Invoke-Expression`/`iex`, download-and-run (`iwr | iex`, `-OutFile`,
  `DownloadString`), `-EncodedCommand`, `Set-ExecutionPolicy`, Defender tampering
  (`Set-MpPreference`), service / scheduled-task / Run-key / `$PROFILE`
  persistence, `Start-Process -Verb RunAs`, and lsass memory dumps.
- cmd.exe deny rules, caught whether typed directly or shelled out from bash via
  `cmd /c`: `del`/`rmdir /s`, `format`, `vssadmin delete shadows`, `bcdedit`,
  `reg add ...\Run`, `schtasks /create`, `sc create`, `net user ... /add`,
  `netsh advfirewall`, `takeown`, `icacls /grant`, and the usual LOLBins
  (`certutil`, `bitsadmin`, `mshta`, `regsvr32`, `rundll32`).
- macOS deny rules: `csrutil disable`, `spctl --master-disable`, `launchctl` and
  LaunchAgents/LaunchDaemons persistence, Keychain extraction via `security`,
  `dscl` user creation, `kextload`, `tccutil reset`, `diskutil erase`, and
  `xattr -d com.apple.quarantine`.
- PowerShell read-only approves so Windows sessions are not prompted for every
  `Get-ChildItem`. Conservative on purpose: only inspection cmdlets and their
  canonical aliases.
- File hook now blocks macOS Keychain databases, Windows registry hives
  (`NTUSER.DAT`, `SAM`, `SYSTEM`), Windows credential vaults, and `.ppk` keys.
- `fish` joins the recognized POSIX-family shells (`sh`, `zsh`, `dash`, `ash`,
  `ksh`), so `fish -c '...'` is unwrapped and `... | fish` is denied like the rest.
- `package.json` and this changelog, so there is finally a version to point at.

### Changed
- `curl` and `wget` auto-approve is now bash-only. On PowerShell those names are
  aliases for `Invoke-WebRequest`, and the old rule cheerfully approved
  `curl <url> -OutFile evil.ps1`. It does not anymore.
- The git force-push and reset guards now see past global options like
  `--no-pager`, `--git-dir=`, and `-C`/`-c`, so `git --no-pager push --force` no
  longer walks straight past them.
- `rm -rf` of a system directory now also covers the macOS roots `/System`,
  `/Library`, `/Applications`, `/Users`, `/Volumes`, and `/private`.

### Fixed
- PowerShell commands containing a backtick are no longer mis-split, so a
  dangerous statement after one cannot hide from the per-statement checks.

### Notes
- Project renamed from `claude-settings` to `shellter`.
- Test suite grew from 173 to 212 cases. The bash path is byte-identical to 0.1.0,
  proven by the original cases still passing untouched.

## [0.1.0] - 2026-05-09

The starting point: everything the hooks did before we began versioning. Two
PreToolUse hooks, `check-bash.js` for commands and `check-sensitive-files.js` for
file access, auto-allowing the safe, blocking the obviously dangerous, and
prompting for everything in between.

This bundles the original hooks and a later hardening pass, since no versions
were cut in between:
- Recursive checking inside `bash -c`, `sh -c`, `find -exec`, `xargs`, and
  `<(...)` / `>(...)` process substitution, so a wrapper cannot hide a payload.
- Symlink resolution in the file hook (`safeRealpath`), defeating the
  `ln -s ~/.env /tmp/x; Read /tmp/x` trick.
- Unicode normalization on command input and steganography detection in written
  content.
- Deny rules for reverse shells, exfiltration, encoded payloads, privilege
  escalation, git identity/hook/credential backdoors, shell-rc and CI-config
  persistence, kernel module load, loader injection, crypto miners, and the
  destructive `rm`/`git push --force`/`reset --hard` family.
- Approves for read-only git, `gh`, `go`, `kubectl`, `terraform`, `helm`, the
  common Python/JS/TS linters and formatters, and standard read-only Unix tools.
- Sensitive-file coverage for keys, credential files, wallets, and browser cookie
  databases, plus prompt-injection and token-shape detection in written content.
- Opt-in audit log via `CLAUDE_HOOK_LOG` and `CLAUDE_HOOK_DEBUG`.

[0.5.0]: https://github.com/walangstudio/shellter/releases/tag/v0.5.0
[0.4.1]: https://github.com/walangstudio/shellter/releases/tag/v0.4.1
[0.4.0]: https://github.com/walangstudio/shellter/releases/tag/v0.4.0
[0.3.0]: https://github.com/walangstudio/shellter/releases/tag/v0.3.0
[0.2.0]: https://github.com/walangstudio/shellter/releases/tag/v0.2.0
[0.1.0]: https://github.com/walangstudio/shellter/releases/tag/v0.1.0
