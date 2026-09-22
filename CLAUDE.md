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
- Never use a bare string as the replacement in String.replace here: a `$` followed by a backtick means "everything before the match" and splices the file into itself. Use a function replacement. This corrupted SECURITY-REVIEW.md and check-bash.js once each.
- When adding a parameter that changes behaviour, update EVERY call site. An omitted third argument read as undefined and turned a PowerShell-only carve-out into a bash auto-approve.
- Classify binary-vs-text by the printable ratio of the NON-NUL bytes. Every rule keyed on the NULs themselves is gameable: a whole-file ratio is diluted by padding, an absolute amount flags binaries carrying strings, and counting or locating them just moves the threshold (a leading block, one past the cap, or one every 32 bytes each walked through it).
- A file presenting itself as a script (shell extension, shell shebang, no extension) must be scanned however binary it looks. Any ratio test is dilutable by non-printable filler; what a script CLAIMS to be is not.
- Never use a printable-BYTE-RANGE test to tell text from binary. It cannot see any script but Latin: one NUL in an accented or CJK file buried it. Test UTF-8 decodability instead.
- Do not commit while a review agent is running against the branch. HEAD moving mid-review cost a round of confusion about which tree was audited.
- Escape the leading dot in an extension regex. `/.(md|c|h)$/` matches any name ending in a single-letter alternative, so `module.pyc` read as text.
- A dotfile has no extension AND is not extensionless. `.env` fell between both branches and skipped silently.
- JS drops the backslash in an unknown escape, so a generator script writing `.` into source emits `.`. Check the regex literal in the file, not the generator.
- Model brace expansion. `{r,}m` runs `rm` while literal matchers see only `{r,}m`; it is shell grammar, not character obfuscation, so no normaliser catches it.
- `at`/`batch` are English words. Any rule matching them at segment start needs a scheduling-shaped-argument guard or it hard-denies prose like `at most`.
- A wrong hard-deny is unappealable, so a dual-use or uncertain shape (rm of a variable target, scheduling, a download-to-disk) should ASK, not deny. Reserve deny for literal near-unambiguous malice.
- A dangerous string can appear as PROSE (commit message, echo, # comment). Match pipeline/exec rules against a command skeleton with quoted bodies and comments stripped; the interpreter recursion still catches quoted code that is actually executed.
- A hook that crashes or hangs fails OPEN (Claude Code treats nonzero/no exit as non-blocking). Validate input types and bound every quantifier: a non-string tool_input field or a huge command must fail safe, not throw or spin.
- merge-settings must MERGE hooks, not replace the key. Replacing deletes other plugins hooks silently; filter out stale shellter entries then append (idempotent).
- A relaxation (skeleton, resolvable-var skip, brace cap) must mirror EXACTLY what the real expander/recursion does. Looser = a bypass. The skeleton strip, rmVarTargetAsk, and the brace round-cap each opened one.
- The interpreter before -c may be a $variable ($SHELL -c). Keying exec-detection on a literal name list misses it.
- typeof [] === object and JSON.stringify drops string keys on an array. Guard Array.isArray before treating a value as a plain object.
- A pipe THROUGH a command wrapper to an interpreter (`| sudo -u root bash`, `| timeout 5 bash`, `| command sh`, `| "bash"`) walks past the regex deny (interpreter not right after `|`) AND the wrapper-keyword approve rule - auto-approved RCE (as root for sudo/doas). Do NOT hand-roll a wrapper prefix in the regex: a regex cannot model a flag whose value is a SEPARATE token (`sudo -u root` - `root` stops the strip before `bash`), so `timeout --signal KILL 5 bash` auto-approved. Detect it tokenized via `stepWrappers` (reuses CMD_WRAPPERS + WRAPPER_VALUE_FLAGS - ONE arity model, not a second regex grammar). Tokenizing also de-quotes `| "bash"`.
- Secret-file coverage lives in TWO independent lists: check-bash.js `SECRET_TOKENS` (gates `cat`/`less` reads) and check-sensitive-files.js `SENSITIVE_*`/`UNIX_SHADOW` (gates `Read`/`Edit`). A credential file must be added to BOTH or one entry point stays open. `/etc/shadow`/`/etc/sudoers`/`/etc/master.passwd` were missing from both; `/etc/passwd` stays allowed (world-readable, no secret).
- Seeding a var to its real value (HOME=os.homedir()) makes it "resolved", so a `rm -rf $HOME` danger check rides entirely on the expanded literal - and `RM_SYSTEM_PREFIX` is Unix-only and lacked `/root`, so a Windows/root home-wipe fell through (regressed 0.7.1's blanket `$VAR` deny). Match the home directory itself (os.homedir(), any OS) and `/root` as rm targets. `tokenizeArgs` MUST match bash double-quote escaping (backslash literal except before `$ \` " \\` newline) - the old "always drop the backslash" ate the separators in `"C:\Users\me"` so the path never matched the home/secret checks; fixing it makes every quoted form (`"$HOME"`, literal quoted home path) deny.
- Do NOT gate the prose-skeleton relaxation on the quote-stripped skeleton to fix the commit-message FP: it strips a QUOTED interpreter word (`"$SHELL" -c`, `"bash" -c` - which still executes) and loses the exec indicator, regressing the quoted-interpreter deny (a pinned r10 test). The raw-gate stays. Accepted known-limit: a message quoting BOTH an interpreter `-c` AND a `curl|bash` pipe hard-denies; a correct fix needs quote-context parsing the project avoids.
- rmVarTargetAsk has no isPosh flag but runs on both tools; varEnv keys PS names lowercased (varKey). Look up a var target under BOTH raw and lowercased keys or a PowerShell `rm -rf $Var` asks spuriously.
- `RM_SYSTEM_PREFIX` denies ANY depth under `/home`/`/root`/`/Users`. On Linux `$HOME` sits there, so `rm -rf ~/.cache/app` (a routine cleanup) wrongly hard-denied - but the DEV/CI-Windows home is `C:\Users\...`, NOT under `/home`, so the suite was GREEN on Windows and RED only on Linux CI. Carve out the user's OWN home subtree (os.homedir(), `..`-guarded so it can't climb out) before the system-prefix deny. Lesson: an rm/path test that depends on os.homedir() must be reasoned for BOTH a `/home/<user>` and a `C:\Users\<user>` home - a Windows-only local run hides the Linux verdict.
- A prefix carve-out (`(nt+'/').startsWith(nh+'/')`) with an EMPTY boundary matches everything: a degenerate `os.homedir()` of `/` normalizes to `` and `("" + '/')` is a prefix of every absolute path, so the own-home carve-out auto-allowed `rm -rf /etc`. Guard the boundary non-empty (`if (nh && ...)`) before using it, and reason every carve-out for its degenerate root value (`/`, ``), not just the normal one.
- `os.homedir()` AND `os.userInfo()` THROW (SystemError/ENOENT) when there is no resolvable home/user - a container uid with no `/etc/passwd` entry and `$HOME` unset (routine under K8s/CI), or a raw `HOME=/` passed through spawn env. An unguarded call in a PreToolUse hook crashes it, and a crashed hook FAILS OPEN. Route every OS-account lookup through a try/catch (`safeHomedir()` -> `''`; wrap the host-var seeding loop) - found only because a degenerate-home test spawned the real hook, never by reading the code.
