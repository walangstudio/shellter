# Changelog

What changed, and when. Versions follow [semver](https://semver.org). While we
are pre-1.0, a minor bump (0.x.0) is where the interesting changes land: new deny
rules, new approves, new platforms.

Nothing was versioned before now, so 0.1.0 is the state the hooks were already in
when we started counting. Everything in this session is 0.2.0.

## [0.5.3] - 2026-07-01

Patch: kills a false positive in the destructive-`rm` guard. `/opt` was in the
any-depth system-directory blocklist, so routine cleanup like `rm -rf
/opt/projs/<repo>/scratch.png` was denied as "destructive rm on system directory"
— but `/opt` is a user-writable software/project area, not a bare system dir. The
guard now blocks only wiping the root (`rm -rf /opt`, `/opt/`, `/opt/*`) or a
`..`-traversal that escapes it (`rm -rf /opt/../etc`), and lets a specific deep
path through. Every other system/home dir (`/etc`, `/usr`, `/home`, `/Users`, `~`,
…) stays strict — including their subpaths.

## [0.5.2] - 2026-06-29

Patch: kills a decode-layer false positive in the prompt-injection scanner. Core
hooks only; no API or config change.

### Fixed
- **High-entropy tokens tripped `homoglyph-mixed-script:decoded`.** The decode-one-
  layer pass matches any 24+ run of base64 characters, so a plain identifier (e.g. a
  27-letter method-name fragment in an `Edit`), a hash, or a minified blob was
  speculatively decoded into random bytes that coincidentally contained a Cyrillic
  letter, and the homoglyph matcher -- which matches any short cross-script letter run
  -- fired on the decoded layer. A pure-ASCII file edit was denied as prompt injection.
  Fix: the **homoglyph** matcher now runs on **literal content only**, not on a decoded
  layer (the random bytes of a decoded identifier are not rendered text, and a homoglyph
  hit there is a coincidental byte run). The rule is unconditional -- not gated on any
  "looks like garbage" property of the decoded bytes, since that signal is attacker-
  controllable and would be an evadable suppression. The other invisible-character
  matchers (bidi-override, variation-selector, zero-width, tag) are **unchanged**: they
  still scan the decoded layer, because those specific code points do not occur in a
  decoded identifier's bytes and so never caused this false positive -- a Trojan-Source
  / invisible-char payload smuggled through base64 is still detected.

### Added
- **Confusable-folding for override detection.** Before `OVERRIDE_RE` runs, Cyrillic and
  Greek letters that imitate ASCII are folded to the letter they spoof, so an override
  phrase disguised with lookalike characters matches the same as its ASCII form. This
  runs on **every layer, including the decoded one**, through the keyword path that
  already scans encoded payloads unconditionally -- so a homoglyph-spoofed override
  hidden in a base64 layer is caught (`instruction-override`), recovering the override
  case the literal-only homoglyph change would otherwise drop, with no evadable gate.
  Only `OVERRIDE_RE` is folded: it matches long multi-word phrases, so folding cannot
  turn real foreign-script prose into a match, and the short role-label matchers are
  left unfolded (a stray Cyrillic `аі:` must not fold into a fake `AI:` label). The fold
  map is the single source of truth for the confusable set the mixed-script detector
  uses, so the two cannot drift; folding is 1:1 and identity on ASCII.

  Note: a **non-keyword** homoglyph spoof (e.g. a credential-phishing lure) hidden in a
  base64 layer is no longer flagged on the decoded layer -- only spoofed override
  phrases are recovered there. Literal-content homoglyph detection is unchanged.

### Tests
- Core hook suite 375 -> 381: a long-identifier no-false-positive case; an invalid-UTF-
  8-padded base64 override that must still be denied; a confusable-spoofed override on
  the literal layer and one hidden in base64 that must still be denied on the decoded
  layer; a bidi-override smuggled through base64 that must still be denied on the decoded
  layer; and a Cyrillic line label that must NOT fold into a fake role label. The
  existing literal homoglyph / bidi / variation-selector deny tests and the base64-
  decode-to-override-phrase deny test still pass.

## [0.5.1] - 2026-06-28

Adapter-only fixes (codex/agy shared shim). The Claude Code plugin and the core
hooks (`hooks/`) are **unchanged from 0.5.0** — a marketplace install is unaffected;
this matters only if you wire the codex or agy adapter from the repo.

### Fixed
- **agy adapter was inert.** Antigravity's `run_command` carries the command in
  `args.CommandLine` (PascalCase), but the shim only read `command`/`cmd`/`script`,
  so every agy command fell through unscreened. Now reads `CommandLine` (and write
  tools' `TargetFile`/`CodeContent`).
- **Native file reads bypassed the rules.** An agent could read `.env` with its own
  `view_file`/`read_file` tool instead of a shell command. The shim now maps native
  read/grep/find tools to shellter's sensitive-file check, so secret reads are
  blocked on the file-tool path too, not just via the shell.
- **agy hook-config corrected.** agy runs the hook command without a shell and does
  not strip quotes, resolving the path relative to `.agents/` — a quoted path
  produced `MODULE_NOT_FOUND` and the hook failed open. Docs now specify an
  unquoted, space-free, forward-slash path and a `.*` matcher (Go regex).

### Tests
- Added codex/agy shim cases for the real agy payload shape (`CommandLine`, native
  `view_file`, `TargetFile`/`CodeContent`): shim suite now 20. Unchanged: core hook
  suite 375, pi adapter 15, opencode adapter 13.

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
  `Copy-Item` evasion). On Windows it maps opencode's `bash` tool to PowerShell so
  PS segmentation applies.
- **pi, codex, and agy (Antigravity CLI) adapters** (`adapters/pi/`,
  `adapters/codex/`, `adapters/agy/`, shared shim `adapters/shared/`). Every other
  agent CLI the user runs now routes through the same shellter detector:
  - **pi** — an extension subscribing to `tool_call`, returning `{ block, reason }`
    on deny/ask (verified against pi 0.80.2's type defs; 11/11 adapter tests).
  - **codex** — a `PreToolUse` command hook (Codex ≥ v0.124.0) via the shared shim;
    `deny` is hard-blocked, Tier-2 `ask` defers to Codex's own approval prompt.
    Shell interception is reliable; `apply_patch` file edits are best-effort.
  - **agy** — a `PreToolUse` hook via the shared shim; honors `deny`/`ask`/`allow`.
    Hook-config keys differ across agy builds, so the install doc says to verify
    against the installed build; the shim itself is field-defensive.
  - The shared `shellter-host-hook.js --host=codex|agy` normalizes each host's
    stdin payload into shellter's Claude-shaped JSON, spawns the existing hooks,
    and emits the host's verdict format (12/12 shared-shim tests).
  An opt-in passthrough LLM judge for the gray zone is still planned.
- **Archive exfil blocked.** `tar`/`zip`/`7z`/`gzip`/`xz`/`zstd`/`Compress-Archive`
  of a secret file or whole secret dir (`tar czf k.tgz ~/.ssh`) is denied — these
  were previously auto-approved.
- **Closed inline-interpreter gaps.** The eval-form set now covers `php -r`,
  `deno eval`, `node --eval`, and `perl -ne`/`-pe` (not just `-c`/`-e`).
- **More .NET reads** — `OpenText`/`OpenRead`/`StreamReader`, not only `ReadAllText`.
- **Leading-redirect reads** (`< .env cat`) are caught.

### Changed
- **Dev-workflow guards now ASK instead of hard-DENY.** `git push` to main / `--force`,
  `git reset --hard`/`clean -f`/`checkout --`, `sudo`, `ssh`/`scp`, SQL `DROP`/`TRUNCATE`,
  and `Start-Process -Verb RunAs` are mistake-guards, not malicious-skill attacks, so
  they surface for in-session approval rather than being blocked outright. Tier-1
  threats (secret exfil, RCE, prompt injection, persistence, miners) stay hard deny,
  and a hard deny on any part of a command always wins over an ask.
- **Fewer false positives.** Only the keys that make git run code as a side effect of
  normal git operations (`credential.helper`, `core.hooksPath`/`sshCommand`/`fsmonitor`,
  `init.templateDir`, `filter.*.clean/smudge`, `!`-aliases) are hard-blocked. The keys a
  developer legitimately sets but an attacker could abuse (`core.editor`/`pager`,
  `sequence.editor`, `diff.external`, `gpg.program`) now **ask** instead of deny.
  `git config user.name/email` is allowed. `.env.example`/`.sample`/`.template` are
  treated as placeholders, not secrets (`cp .env.example .env` is allowed). `credentials`
  only counts as a path segment or a file with an extension, so `rg credentials src/` is
  fine. Plain `curl`/`wget` POSTs are allowed; only uploads that reference a secret are
  blocked.

### Notes
- Detection stays pattern + heuristic. A determined agent that runs arbitrary code (a
  custom `python`/`node` script, an obfuscated path) can still read a file — no
  command-pattern hook fully prevents that. The real boundary for "the agent must
  never see this secret" is not exposing it to the agent (sandbox / secret manager);
  shellter raises the bar against the casual and obvious paths.
- **Evasions closed in security review** of the above: a secret after a quoted `;`
  inside an inline interpreter (`python -c "import os; open('.env')"`), a secret read
  via a copy *target* flag (`cp -t /exfil ~/.ssh/id_rsa`, `cp --target-directory=…`),
  and `scp`/`sftp` of a secret (hard-deny, above the plain remote-transfer ask).
- Test suite grew 329 -> 375 (hook), plus adapter suites (pi 11, shared codex/agy 12,
  opencode). The bash path stays byte-compatible for pre-existing cases.

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

[0.5.2]: https://github.com/walangstudio/shellter/releases/tag/v0.5.2
[0.5.1]: https://github.com/walangstudio/shellter/releases/tag/v0.5.1
[0.5.0]: https://github.com/walangstudio/shellter/releases/tag/v0.5.0
[0.4.1]: https://github.com/walangstudio/shellter/releases/tag/v0.4.1
[0.4.0]: https://github.com/walangstudio/shellter/releases/tag/v0.4.0
[0.3.0]: https://github.com/walangstudio/shellter/releases/tag/v0.3.0
[0.2.0]: https://github.com/walangstudio/shellter/releases/tag/v0.2.0
[0.1.0]: https://github.com/walangstudio/shellter/releases/tag/v0.1.0
