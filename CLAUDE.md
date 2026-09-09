# CLAUDE.md

Claude Code security hooks: PreToolUse gates on `Bash`/`PowerShell` and the file tools, plus
a pre-install bundle auditor. Zero dependencies, Node >= 18, cross-platform.

- `hooks/` - the shipped code. `check-bash.js` (command gating), `check-sensitive-files.js`
  (file tools), `scan-content.js` (shared pure scanner, no I/O), `shellter-trust.js`
  (content-hash trust store + CLI), `shellter-scan.js` (bundle audit CLI), `hooks.json`
  (plugin registration).
- `adapters/` - codex/agy shim plus opencode/pi TypeScript adapters.
- `test-hooks.js` - the entire suite. One file, hand-rolled runner, no framework.

## The loop

```bash
node test-hooks.js                        # the suite; exits 1 on any failure
node adapters/shared/test-host-hook.js     # adapter shim; NOT in `npm test`
node --check hooks/<file>.js               # after any edit, before running anything
```

Both must be green. CI runs both on ubuntu 18/20/22/24 and windows 20.

## Dependencies

There are none, and that is a feature. `package.json` has no `dependencies` or
`devDependencies` key. Every `require()` is a Node builtin or a relative path.

`npm audit` fails with `ENOLOCK`. That is the correct result, not a problem to fix - do not
create a lockfile to make it quiet.

The only third-party surface is the GitHub Actions in `.github/workflows/`. Check those for
staleness; nothing else can carry a CVE.

## Verdicts

Four outcomes, and the difference matters more than it looks:

| verdict | meaning |
| --- | --- |
| `deny` | hard block, **unappealable in-session** |
| `ask` | surfaced for approval |
| `allow` | auto-approved, no prompt |
| fallthrough | exit 0 with no stdout, Claude's normal prompt |

Prefer `ask` over `deny` whenever the analysis is uncertain - a wrong `deny` cannot be
overridden, a wrong `ask` costs one keystroke.

`allow` and fallthrough are **not** the same, and neither is safe by default: under a broad
`Read(*)`/`Bash(*)` allow rule or an auto-accept mode, a fallthrough is a silent allow. A
ceiling the engine hit is not evidence the part it skipped was clean - record a coverage gap
and degrade to `ask` instead.

## Failure log

Every line here exists because it went wrong at least once.

- `test-hooks.js` is CRLF. Insert generated blocks with `\r\n` or the anchor match silently finds nothing.
- Never write a dangerous literal into a test or a rule pattern directly: assemble it with `join()`, or the file trips the detectors when a hook scans it.
- Verify a rule by running the real hook with a JSON payload on stdin. Reasoning about the regex is how both the variable-indirection bypass and the apostrophe bypass survived review.
- Never re-add a self-exemption for shellter's own files. It was tried, and reverted as a confirmed security regression. The scanner lighting up its own detector source is correct.
- Measure hook cost with interleaved medians, never two sequential loops. Node spawn (~520 ms on Windows) is ~95% of a call and drifts enough between runs to invent a regression that is not there.
- Gate every new scan view behind a cheap prefilter (non-ASCII probe, directive match) so plain-ASCII content pays nothing.
- Dedupe findings on signal **and** severity. The same signal is emitted at two severities by context, so keying on the name alone silently drops an escalation.
- The approve floor must step over wrappers and shell keywords before looking for the command word. `timeout 5 cat $X` and `do cat $f` walked past a first-token check.
- An assignment persists to later segments only when the segment is assignments and nothing else; a brace group counts, a subshell and a command prefix do not.
- `git config` is blocked by shellter's own rules in this tree. Use `F:\bin\ghc.bat kitty` from inside the repo to set identity.
- Any check that asks "is this variable resolved?" must mirror `VAR_AT` exactly. `${X:-d}`, `${X#p}`, `${X/a/b}` and `${X:0:9}` are never expanded, so treating them as resolved auto-approves a secret read.
- Classify files by content, not extension. Selecting scan targets by suffix meant renaming `hook.sh` to `hook` skipped it entirely, with no gap recorded.
- `#!/usr/bin/env node` is not a shell script. Listing `env` in a shebang alternation matches every Node CLI and scans it with shell rules.
- Bound every regex repetition that can match attacker-controlled text. Unbounded `{2,}` in the var-composed rule was quadratic: 24KB stalled the hook 22 seconds.
- Resolve a variable alias one hop only, against names already known. General re-expansion of computed values would break the invariant that expansion reveals only text the user literally typed.
- The PowerShell branch of `checkSegmentApprove` returns before the bash floor. Any new floor must be added to BOTH paths or it is dead code on one of them.
- Hooks are stateless but PowerShell variables persist across tool calls. A cross-segment guard proves nothing about an attacker who just sends two separate calls.
- A `:` after a PowerShell variable name means a namespace (`$env:`, `$using:`), not that variable. Expanding it splices the local value in and hard-denies a safe command.
- Treat an embedded NUL in otherwise-printable text as obfuscation, not as a binary. `. script` and `cat script | bash` execute straight past it.
- UTF-16 is ~50% NUL by construction, so any printable-ratio binary test skips every UTF-16 file. Windows PowerShell writes UTF-16LE from Out-File by default - decode before classifying.
