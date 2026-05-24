# Changelog

What changed, and when. Versions follow [semver](https://semver.org). While we
are pre-1.0, a minor bump (0.x.0) is where the interesting changes land: new deny
rules, new approves, new platforms.

Nothing was versioned before now, so 0.1.0 is the state the hooks were already in
when we started counting. Everything in this session is 0.2.0.

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

[0.2.0]: https://github.com/walangstudio/shellter/releases/tag/v0.2.0
[0.1.0]: https://github.com/walangstudio/shellter/releases/tag/v0.1.0
