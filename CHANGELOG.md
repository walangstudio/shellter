# Changelog

What changed, and when. Versions follow [semver](https://semver.org): a major
bump means a deny rule got stricter or an approve rule got narrower, so something
that used to slide through now stops at the door.

The first three releases below were reconstructed from git history. We started
counting properly at 2.0.0.

## [2.0.0] - 2026-05-24

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
- Test suite grew from 173 to 212 cases. The bash path is byte-identical to 1.1.0,
  proven by the original cases still passing untouched.

## [1.1.0] - 2026-05-09

Hardening pass. Closed a batch of known bypasses and cut down on needless prompts.

### Added
- Recursive checking inside `bash -c`, `sh -c`, `find -exec`, `xargs`, and
  `<(...)` / `>(...)` process substitution, so a wrapper cannot hide a payload.
- Symlink resolution in the file hook (`safeRealpath`), defeating the
  `ln -s ~/.env /tmp/x; Read /tmp/x` trick.
- Unicode normalization on command input and steganography detection in written
  content (zero-widths, bidi overrides, tag chars).
- Deny categories: git identity/hook/credential backdoors, shell-rc and CI-config
  writes, kernel module load, loader injection, crypto miners, alternative
  scheduling, debugger attach.
- Approve categories: more read-only git, `gh`, `go`, `kubectl`, `terraform`,
  `helm`, the common Python/JS/TS linters and formatters, `pnpm`/`bun` build and
  test, `pre-commit`.
- Sensitive-file coverage for `.git-credentials`, `.npmrc`, `.pypirc`,
  `.cargo/credentials`, `.docker/config.json`, wallets, and browser cookie
  databases, plus their backup forms.
- Prompt-injection coverage: jailbreak phrases, role-tag injection, fake tool-call
  tags, markdown `javascript:` URLs, ANSI escapes. Token-shape grep blocking for
  AWS, GitHub, Slack, JWT, and Bearer tokens.
- Opt-in audit log via `CLAUDE_HOOK_LOG` and `CLAUDE_HOOK_DEBUG`.

### Changed
- Settings template uses a `__HOME__` placeholder instead of a hardcoded path.
- Test suite grew from 57 to 164 cases.

## [1.0.0] - 2026-04-03

First version. Two PreToolUse hooks: `check-bash.js` for commands and
`check-sensitive-files.js` for file access. Auto-allow the safe, block the
obviously dangerous, prompt for everything in between.

[2.0.0]: https://github.com/walangstudio/shellter/releases/tag/v2.0.0
[1.1.0]: https://github.com/walangstudio/shellter/releases/tag/v1.1.0
[1.0.0]: https://github.com/walangstudio/shellter/releases/tag/v1.0.0
