#!/usr/bin/env node
// PreToolUse hook for Bash and PowerShell (matcher "Bash|PowerShell").
// For the Bash tool: Unix/macOS semantics -- splits chains and recurses into
// `bash -c`, `find -exec`, `xargs`, `<(...) / >(...)`, and any `powershell -c`
// / `cmd /c` it shells out to. For the PowerShell tool: PowerShell semantics
// (backtick escape, no POSIX quoting), the PowerShell/cmd deny+approve sets, and
// the cross-platform deny rules (git guards, miners, etc.) apply too.
// The bash path is unchanged from before tool_name branching was added.
// CLAUDE_HOOK_LOG=/path or CLAUDE_HOOK_DEBUG=1 to record decisions.

'use strict';

const fs = require('fs');

function audit(decision, reason, snippet) {
  const log = process.env.CLAUDE_HOOK_LOG;
  const debug = process.env.CLAUDE_HOOK_DEBUG;
  if (!log && !debug) return;
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    hook: 'check-bash',
    decision,
    reason,
    snippet: String(snippet || '').slice(0, 500),
  });
  if (log) {
    try { fs.appendFileSync(log, line + '\n'); } catch {}
  }
  if (debug) {
    try { process.stderr.write(line + '\n'); } catch {}
  }
}

// Strip invisible/steganographic chars so `b<U+200B>ash -c …` can't slip past regex.
function normalizeUnicode(s) {
  if (typeof s !== 'string') return s;
  return s
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/[‪-‮⁦-⁩]/g, '')
    .replace(/[​-‍⁠﻿]/g, '')
    .replace(/[  -   　]/g, ' ');
}

function splitChainSegments(cmd) {
  const len = cmd.length;
  let i = 0;
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let segmentStart = 0;
  const segments = [];

  while (i < len) {
    const ch = cmd[i];
    const next = i + 1 < len ? cmd[i + 1] : '';

    if (inSingle) {
      if (ch === "'") inSingle = false;
      i++;
      continue;
    }

    if (ch === "'" && !inDouble && !inBacktick) {
      inSingle = true;
      i++;
      continue;
    }

    if (ch === '\\' && inDouble) {
      i += 2;
      continue;
    }

    if (ch === '"' && !inBacktick) {
      inDouble = !inDouble;
      i++;
      continue;
    }

    if (inDouble) {
      i++;
      continue;
    }

    if (ch === '`') {
      inBacktick = !inBacktick;
      i++;
      continue;
    }

    if (inBacktick) {
      i++;
      continue;
    }

    if (ch === '$' && next === '(') {
      depth++;
      i += 2;
      continue;
    }
    if ((ch === '<' || ch === '>') && next === '(') {
      depth++;
      i += 2;
      continue;
    }
    if (ch === '(') {
      depth++;
      i++;
      continue;
    }
    if (ch === ')' && depth > 0) {
      depth--;
      i++;
      continue;
    }

    if (depth === 0) {
      if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
        segments.push(cmd.slice(segmentStart, i));
        i += 2;
        segmentStart = i;
        continue;
      }
      if (ch === ';' && next !== ';') {
        segments.push(cmd.slice(segmentStart, i));
        i++;
        segmentStart = i;
        continue;
      }
    }

    i++;
  }

  segments.push(cmd.slice(segmentStart));
  return segments.map(s => s.trim()).filter(s => s.length > 0);
}

function extractParenContent(value, openIdx) {
  let i = openIdx + 1;
  let depth = 1;
  let inSingle = false;
  let inDouble = false;

  while (i < value.length && depth > 0) {
    const ch = value[i];

    if (inSingle) {
      if (ch === "'") inSingle = false;
      i++;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      i++;
      continue;
    }
    if (ch === '\\' && inDouble) {
      i += 2;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      i++;
      continue;
    }
    if (inDouble) {
      i++;
      continue;
    }
    if (ch === '(') {
      depth++;
      i++;
      continue;
    }
    if (ch === ')') {
      depth--;
      if (depth === 0) {
        return { inner: value.slice(openIdx + 1, i), end: i + 1 };
      }
      i++;
      continue;
    }
    i++;
  }
  return null;
}

// Returns {innerCmd, opaque} for `bash -c '...'` style invocations, or null.
function parseShellCInvocation(segment) {
  const m = segment.match(
    /^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish)\s+(?:-[a-zA-Z]*c|--command)\s+(.+)$/
  );
  if (!m) return null;
  const arg = m[2].trim();

  if (arg.startsWith("'")) {
    // Walk through, supporting POSIX `'\''` apostrophe escape (close, escape, reopen).
    let i = 1;
    let inner = '';
    while (i < arg.length) {
      if (arg[i] === "'") {
        if (arg.slice(i, i + 4) === "'\\''") {
          inner += "'";
          i += 4;
          continue;
        }
        return { innerCmd: inner, opaque: false };
      }
      inner += arg[i];
      i++;
    }
    return { innerCmd: null, opaque: true };
  }

  if (arg.startsWith('"')) {
    let i = 1;
    while (i < arg.length) {
      if (arg[i] === '\\') { i += 2; continue; }
      if (arg[i] === '"') break;
      i++;
    }
    if (i >= arg.length) return { innerCmd: null, opaque: true };
    const inner = arg.slice(1, i);
    if (/\$\(|`|\$\{|\$[A-Za-z_]/.test(inner)) {
      return { innerCmd: null, opaque: true };
    }
    return { innerCmd: inner, opaque: false };
  }

  if (/^\$/.test(arg) || /\$\(|`/.test(arg)) {
    return { innerCmd: null, opaque: true };
  }
  return { innerCmd: arg, opaque: false };
}

// Returns array of inner commands from each `-exec ... \;` / `+` clause.
function parseFindExec(segment) {
  if (!/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*find\b/.test(segment)) return null;
  const results = [];
  const re = /\s-(?:exec(?:dir)?|ok(?:dir)?)\s+(.+?)\s+(?:\\;|\+)(?=\s|$)/g;
  let m;
  while ((m = re.exec(segment)) !== null) {
    results.push(m[1].trim());
  }
  return results.length ? results : null;
}

// Returns the inner command string from `xargs [opts] CMD ARGS`.
function parseXargs(segment) {
  const stripped = segment.replace(/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*/, '');
  if (!/^xargs\b/.test(stripped)) return null;
  const tokens = stripped.split(/\s+/);
  if (tokens[0] !== 'xargs') return null;
  const valueFlags = new Set(['-I', '-n', '-P', '-d', '-E', '-s', '-L']);
  let i = 1;
  while (i < tokens.length) {
    const tok = tokens[i];
    if (!tok.startsWith('-')) break;
    if (tok.startsWith('--') && tok.includes('=')) { i++; continue; }
    if (tok.startsWith('--')) { i++; continue; }
    if (tok.length > 2 && valueFlags.has(tok.slice(0, 2))) { i++; continue; }
    if (tok.length === 2 && valueFlags.has(tok) && i + 1 < tokens.length) { i += 2; continue; }
    i++;
  }
  if (i >= tokens.length) return null;
  return tokens.slice(i).join(' ');
}

function extractProcessSubstitutions(segment) {
  const results = [];
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  while (i < segment.length) {
    const ch = segment[i];
    const next = segment[i + 1] || '';
    if (inSingle) {
      if (ch === "'") inSingle = false;
      i++;
      continue;
    }
    if (ch === "'" && !inDouble) { inSingle = true; i++; continue; }
    if (ch === '\\' && inDouble) { i += 2; continue; }
    if (ch === '"') { inDouble = !inDouble; i++; continue; }
    if (inDouble) { i++; continue; }
    if ((ch === '<' || ch === '>') && next === '(') {
      const r = extractParenContent(segment, i + 1);
      if (r) {
        results.push(r.inner);
        i = r.end;
        continue;
      }
    }
    i++;
  }
  return results;
}

// PowerShell statement splitter. PS quoting differs from POSIX: backtick is the
// escape char (not command substitution), single quotes are fully literal (no
// `'\''`), double quotes honor backtick escapes and `$(...)` subexpressions.
// Splits on `;`, and on PS7 `&&` / `||`, at subexpression depth 0.
function splitPoshSegments(cmd) {
  const len = cmd.length;
  let i = 0;
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let segmentStart = 0;
  const segments = [];

  while (i < len) {
    const ch = cmd[i];
    const next = i + 1 < len ? cmd[i + 1] : '';

    if (inSingle) {
      if (ch === "'") inSingle = false;
      i++;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = true;
      i++;
      continue;
    }
    if (ch === '`') {
      // Backtick escapes the next char (inside or outside double quotes).
      i += 2;
      continue;
    }
    if (ch === '"') {
      inDouble = !inDouble;
      i++;
      continue;
    }
    if (inDouble) {
      if (ch === '$' && next === '(') { depth++; i += 2; continue; }
      if (ch === ')' && depth > 0) { depth--; }
      i++;
      continue;
    }
    if (ch === '$' && next === '(') { depth++; i += 2; continue; }
    if (ch === '(') { depth++; i++; continue; }
    if (ch === ')' && depth > 0) { depth--; i++; continue; }

    if (depth === 0) {
      if ((ch === '&' && next === '&') || (ch === '|' && next === '|')) {
        segments.push(cmd.slice(segmentStart, i));
        i += 2;
        segmentStart = i;
        continue;
      }
      if (ch === ';') {
        segments.push(cmd.slice(segmentStart, i));
        i++;
        segmentStart = i;
        continue;
      }
    }
    i++;
  }

  segments.push(cmd.slice(segmentStart));
  return segments.map(s => s.trim()).filter(s => s.length > 0);
}

// Returns {innerCmd, opaque} for `powershell -Command '...'` / `pwsh -c "..."`,
// or null. Mirrors parseShellCInvocation but for PS-style invocations reached
// from inside another shell command.
function parsePoshInvocation(segment) {
  const m = segment.match(
    /^\s*(?:[^\s]*[\\/])?(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\s+(?:-[A-Za-z]+\s+(?!-)\S+\s+)*-(?:c|command)\b\s+(.+)$/i
  );
  if (!m) return null;
  const arg = m[1].trim();
  // -EncodedCommand / opaque expansion is handled by deny patterns; here we just
  // surface the inner string when it is a plain quoted literal.
  if (arg.startsWith("'")) {
    const end = arg.indexOf("'", 1);
    if (end === -1) return { innerCmd: null, opaque: true };
    return { innerCmd: arg.slice(1, end), opaque: false };
  }
  if (arg.startsWith('"')) {
    const end = arg.indexOf('"', 1);
    if (end === -1) return { innerCmd: null, opaque: true };
    const inner = arg.slice(1, end);
    if (/\$\(|`/.test(inner)) return { innerCmd: null, opaque: true };
    return { innerCmd: inner, opaque: false };
  }
  return { innerCmd: arg, opaque: false };
}

// Returns the inner command string from `cmd /c "..."` / `cmd.exe /k ...`, or null.
function parseCmdInvocation(segment) {
  const m = segment.match(
    /^\s*(?:[^\s]*[\\/])?cmd(?:\.exe)?\s+(?:\/[a-zA-Z]\s+)*\/[ckCK]\b\s+(.+)$/
  );
  if (!m) return null;
  let arg = m[1].trim();
  if (arg.startsWith('"') && arg.endsWith('"') && arg.length > 1) {
    arg = arg.slice(1, -1);
  }
  return { innerCmd: arg, opaque: false };
}

function deny(reason, snippet) {
  audit('deny', reason, snippet);
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  });
  process.stdout.write(output + '\n');
  process.exit(0);
}

function approve(snippet) {
  audit('allow', 'Auto-approved by hook', snippet);
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'allow',
      permissionDecisionReason: 'Auto-approved by hook',
    },
  });
  process.stdout.write(output + '\n');
  process.exit(0);
}

const DENY_PATTERNS = [
  // Encoded payload execution
  [/(base64|b64)\s*(--)?d(ecode)?\s*.*\|\s*(?:(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish|python[23]?|perl|ruby|node|deno|bun|php|lua|tclsh)|eval)\b/i,
    'Encoded payload piped to shell blocked'],
  [/\becho\s+.*\|\s*(base64|xxd)\s.*\|\s*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish)\b/i,
    'Encoded execution chain blocked'],

  // eval (targeted)
  [/^\s*eval\s/, 'eval as command blocked -- use explicit commands instead'],
  [/\beval\s+.*(\$[({]|`)/, 'eval with dynamic content blocked -- possible injection'],
  [/\beval\s+.*\b(base64|decode|atob)\b/i, 'eval with encoded payload blocked'],

  // Reverse shells
  [/bash\s+-i\s+.*>\/dev\/tcp\//, 'Reverse shell pattern blocked'],
  [/\/dev\/(tcp|udp)\//, 'Direct /dev/tcp or /dev/udp access blocked'],
  [/\b(nc|ncat|netcat|socat)\s+.*-[a-zA-Z]*e\s/i, 'Netcat with -e blocked -- possible reverse shell'],
  [/python[23]?\s+-c\s+.*\b(socket|pty\.spawn|subprocess)\b/i, 'Python one-liner with socket/pty/subprocess blocked'],
  [/perl\s+-e\s+.*\bsocket\b/i, 'Perl socket one-liner blocked'],
  [/ruby\s+-e\s+.*\bTCPSocket\b/i, 'Ruby TCPSocket one-liner blocked'],

  // Data exfiltration
  [/\bcurl\s+.*(-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)[\s='"]/i,
    'curl with data upload blocked -- review manually'],
  [/\bwget\s+.*--post-(data|file)/i, 'wget POST blocked -- review manually'],

  // Download-and-execute / pipe-to-interpreter (incl. absolute paths)
  [/\b(curl|wget)\s+.*\|\s*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish|python[23]?|perl|ruby|node|deno|bun|php|lua|tclsh)\b/i,
    'Download-and-execute pipe blocked -- inspect script first'],
  // Generic pipe-to-interpreter: end-of-segment or -c/-i/-s flag (no script arg).
  [/\|\s*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish|python[23]?|perl|ruby|node|deno|bun|php|lua|tclsh)\s*$/i,
    'Pipe to bare shell/interpreter blocked'],
  [/\|\s*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish|python[23]?|perl|ruby|node|deno|bun|php|lua|tclsh)\s+(-[a-zA-Z]*c|-i|-s)\b/i,
    'Pipe to interpreter with -c/-i/-s blocked'],
  // Process substitution as input to source/. or a shell.
  [/\b(source|\.)\s+<\(/, 'source/. of process substitution blocked'],
  [/^\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:[^\s]*\/)?(bash|sh|zsh|dash|ash|ksh|fish)\s+<\(/i,
    'Shell with process-substitution input blocked'],

  // Persistence
  [/(crontab|\/etc\/cron|\/etc\/systemd|\/etc\/init\.d|\/etc\/rc\.local)/i,
    'Modifying cron/systemd/init blocked -- possible persistence'],
  [/(>|>>|tee\s+(-a)?)\s*\/etc\//i, 'Writing to /etc blocked'],
  [/(>|>>|tee\s+(-a)?)\s*[^\s|;&]*\.(bashrc|zshrc|profile|bash_profile|zprofile|zshenv|zlogin|kshrc|cshrc|inputrc|fishrc|config\.fish)\b/i,
    'Writing to shell rc file blocked -- possible persistence'],
  [/(>|>>|tee\s+(-a)?|cp\s|mv\s)\s*[^\n|;&]*\.git\/hooks\//i,
    'Writing to .git/hooks blocked -- possible persistence'],
  [/(>|>>|tee\s+(-a)?|cp\s|mv\s)\s*[^\n|;&]*(\.github\/workflows\/|\.gitlab-ci\.yml|\.circleci\/config|Jenkinsfile|\.drone\.yml|\.azure-pipelines\.yml|\.woodpecker\.yml|buildkite\.yml)\b/i,
    'Writing to CI config blocked -- possible supply-chain attack'],

  // Privilege escalation / identity tampering
  [/^\s*sudo\s/, 'sudo blocked -- run privileged commands manually'],
  // 4-digit numeric mode whose leading bit is 2/4/6/7 sets setuid/setgid/sticky.
  [/\bchmod\s+0?[2467][0-7]{3}\b/, 'chmod with setuid/setgid bit blocked'],
  [/\bchmod\s+[ugoa]*[+=]\S*s\b/, 'chmod setuid/setgid (symbolic) blocked'],
  [/^\s*(chsh|usermod|useradd|userdel|groupadd|groupdel|passwd|visudo|gpasswd|adduser|deluser)\b/,
    'User/group modification blocked'],
  [/^\s*(insmod|rmmod|modprobe|kexec)\b/, 'Kernel module / kexec blocked'],
  [/\b(LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)\s*=\S/i,
    'Loader-injection environment variable blocked'],
  [/^\s*(at|batch|systemd-run)\s/, 'Alternative scheduling (at/batch/systemd-run) blocked'],
  [/\b(strace|ltrace|gdb)\s+.*-p\s+\d/i, 'Attaching debugger/tracer to running process blocked'],

  // Identity / git backdoor
  [/git\s+config\s+(--global\s+|--system\s+)?(user\.(email|name|signingkey)|gpg\.program|core\.hooksPath|core\.editor|core\.sshcommand|credential\.helper|alias\.\S+\s+!)/i,
    'git config of identity / hook / credential helper blocked -- possible backdoor'],

  // Environment exfiltration
  [/\b(env|printenv|set)\b.*\|\s*(curl|wget|nc|netcat|ncat|socat)/i,
    'Piping environment to network tool blocked'],

  // SSH / lateral movement
  [/^\s*(ssh|scp|sftp)\s/, 'SSH/SCP blocked -- run manually'],

  // Supply chain
  [/\b(pip|pip3|npm|yarn|pnpm|bun)\s+install\s+.*https?:\/\//i,
    'Installing packages from raw URLs blocked'],
  [/\b(curl|wget)\s+.*\.(sh|py|rb|pl)\b.*-o\s/i, 'Downloading executable script for later run -- review manually'],

  // Container escape
  [/docker\s+run\s+.*--privileged/i, 'Privileged docker run blocked'],
  [/docker\s+run\s+.*-v\s+\/:\//i, 'Docker host root mount blocked'],

  // Process injection
  [/\/proc\/[0-9]+\/(mem|maps|cwd|root|exe)|ptrace/, 'Process memory access blocked'],

  // Disk operations
  [/\b(mkfs|fdisk|parted|wipefs|shred)\b/i, 'Disk/partition/wipe operations blocked'],
  [/\bdd\s+if=/i, 'dd disk operation blocked'],

  // Firewall
  [/\b(iptables|nftables|ufw|firewall-cmd|pfctl)\b/i, 'Firewall modification blocked'],

  // Git destructive. The prefix group eats global options that can sit between
  // `git` and the subcommand -- `-C <path>`, `-c <cfg>`, `-p/-P`, and long flags
  // like `--no-pager` / `--git-dir=...` -- so e.g. `git --no-pager push -f` and
  // `git -C /repo push -f` are both still caught.
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*push\s+.*\b(main|master)\b/, 'git push to main/master blocked -- push to a feature branch'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*push\s+origin\s*$/, 'git push to default branch blocked'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*push\s+.*--force(?!-with-lease)/, 'git push --force blocked'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*push\s+(?:\S+\s+)*-f\b/, 'git push -f blocked'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*reset\s+--hard/, 'git reset --hard blocked -- can destroy uncommitted work'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*clean\s+-[a-zA-Z]*f/, 'git clean -f blocked -- deletes untracked files'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*checkout\s+--\s/, 'git checkout -- blocked -- discards uncommitted changes'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*update-ref\s+-d\b/, 'git update-ref -d blocked -- destroys refs'],
  [/git\s+(?:(?:-[cC]\s+\S+|--[a-z][\w-]*(?:=\S+)?|-[pP])\s+)*filter-(branch|repo)\b/, 'git filter-branch / filter-repo blocked -- rewrites history'],

  // Sensitive file reads via shell
  [/(cat|less|more|head|tail|bat|vi|vim|nano|sed|awk|grep|rg)\s+.*\.(env|pem|key|crt|secret|credentials|pgpass|netrc|npmrc|p12|pfx|jks)\b/i,
    'Reading sensitive file via shell blocked'],
  [/(cat|less|more|head|tail|bat|vi|vim|nano|sed|awk|grep|rg)\s+.*(\.env|\.secret|credentials|id_rsa|id_ed25519|id_ecdsa|\.ssh\/|\.gnupg\/|\.aws\/|\.gcloud\/|\.azure\/|\.docker\/config|\.gitconfig|\.git-credentials)/i,
    'Reading sensitive file/directory via shell blocked'],

  // Destructive rm
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+(\/|\/home|\/etc|\/usr|\/var|\/boot|\/sys|\/proc|\/dev|\/opt|\/lib|\/bin|\/sbin|\/System|\/Library|\/Applications|\/Users|\/Volumes|\/private|\/cores)\b/,
    'Destructive rm on system directory blocked'],
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+~\b/, 'Destructive rm on home directory blocked'],
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+(\{\}|\$\{?[A-Za-z_])/,
    'rm -rf with placeholder/variable target blocked'],
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+\/\*/, 'rm -rf /* blocked'],

  // SQL destructive
  [/\b(drop|truncate)\s+(database|table|schema)\b/i, 'DROP/TRUNCATE blocked'],

  // Cryptocurrency miners
  [/\b(xmrig|minerd|cgminer|bfgminer|ethminer|t-rex|nbminer|lolminer|phoenixminer|gminer|teamredminer)\b/i,
    'Cryptocurrency miner binary blocked'],
  [/\bstratum\+(tcp|ssl|tls):\/\//i, 'stratum mining pool URL blocked'],

  // Suspicious ssh-keygen targets
  [/ssh-keygen\s+.*-f\s+\/(tmp|var|opt|dev)\//i, 'ssh-keygen writing to system temp blocked'],

  // macOS: security posture tampering
  [/\bcsrutil\s+disable\b/i, 'csrutil disable blocked -- disables System Integrity Protection'],
  [/\bspctl\s+--master-disable\b/i, 'spctl --master-disable blocked -- disables Gatekeeper'],
  [/\btccutil\s+reset\b/i, 'tccutil reset blocked -- clears privacy/TCC grants'],
  [/\bnvram\s+.*boot-args/i, 'nvram boot-args modification blocked'],
  [/\bxattr\s+.*-d\s+com\.apple\.quarantine/i, 'Stripping com.apple.quarantine blocked'],
  // macOS: persistence
  [/\blaunchctl\s+(load|bootstrap|enable|submit)\b/i, 'launchctl load/bootstrap blocked -- possible persistence'],
  [/(>|>>|tee\s+(-a)?|cp\s|mv\s)\s*[^\n|;&]*\/Library\/Launch(Agents|Daemons)\//i,
    'Writing to LaunchAgents/LaunchDaemons blocked -- possible persistence'],
  // macOS: kexts / disks / accounts
  [/\b(kextload|kmutil\s+load)\b/i, 'Kernel extension load blocked'],
  [/\bdiskutil\s+(eraseDisk|eraseVolume|partitionDisk|reformat)\b/i, 'diskutil erase/partition blocked'],
  [/\bdscl\s+\.\s+-create\s+\/Users\//i, 'dscl user creation blocked'],
  // macOS: Keychain secret extraction
  [/\bsecurity\s+(dump-keychain|export\b|find-(generic|internet)-password\s+.*-w\b)/i,
    'Keychain secret extraction via security blocked'],
];

// PowerShell-specific deny patterns. Anchored to PS syntax (verb-noun cmdlets,
// PS flags) so they do not match ordinary bash commands and are safe to run on
// both tools.
const POSH_DENY_PATTERNS = [
  // Destructive recursive/forced removal of home / drive root / wildcard.
  [/\b(Remove-Item|ri|rmdir|rd|del|erase)\b[^;|]*-(?:Recurse|rec)\b[^;|]*-(?:Force|for)\b[^;|]*(\$HOME|\$env:USERPROFILE|\$env:SystemRoot|[A-Za-z]:\\?(\s|$|\*)|\*)/i,
    'Destructive PowerShell removal of home/root/wildcard blocked'],
  [/\b(Remove-Item|ri)\b[^;|]*-(?:Force|for)\b[^;|]*-(?:Recurse|rec)\b[^;|]*(\$HOME|\$env:USERPROFILE|[A-Za-z]:\\?(\s|$|\*)|\*)/i,
    'Destructive PowerShell removal of home/root/wildcard blocked'],
  // Invoke-Expression of dynamic/downloaded content.
  [/\bInvoke-Expression\b|\biex\s*[\(\$"']|\|\s*iex\b/i,
    'Invoke-Expression / iex blocked -- possible dynamic code execution'],
  // Download-and-execute and web data upload.
  [/\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget)\b[^;|]*\|\s*iex\b/i,
    'Download piped to Invoke-Expression blocked'],
  [/\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|curl|wget)\b[^;|]*-OutFile\b/i,
    'PowerShell web download (-OutFile) blocked -- inspect first'],
  [/\.(DownloadString|DownloadFile|DownloadData)\s*\(/i, 'Net.WebClient download blocked'],
  [/\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^;|]*-(Method\s+(POST|PUT)|Body|InFile)\b/i,
    'PowerShell web upload blocked -- review manually'],
  // Encoded command execution.
  [/\b(powershell|pwsh)(\.exe)?\b[^;|]*-(?:e|ec|enc|encodedcommand)\b/i,
    'powershell -EncodedCommand blocked'],
  [/-(?:w(?:indowstyle)?)\s+hidden\b/i, 'powershell -WindowStyle hidden blocked'],
  // Execution policy / security tooling tampering.
  [/\bSet-ExecutionPolicy\b/i, 'Set-ExecutionPolicy blocked'],
  [/\b(Add|Set)-MpPreference\b/i, 'Defender (Add/Set-MpPreference) tampering blocked'],
  // Persistence: services, scheduled tasks, registry Run keys, $PROFILE.
  [/\b(New|Set)-Service\b/i, 'Service creation/modification blocked -- possible persistence'],
  [/\bRegister-ScheduledTask\b/i, 'Register-ScheduledTask blocked -- possible persistence'],
  [/\b(Set|New)-ItemProperty\b[^;|]*\\(Run|RunOnce)\b/i, 'Registry Run-key write blocked -- possible persistence'],
  [/\b(Add-Content|Set-Content|Out-File|Tee-Object)\b[^;|]*\$PROFILE\b/i, 'Writing to $PROFILE blocked -- possible persistence'],
  // Elevation / credential theft.
  [/\bStart-Process\b[^;|]*-Verb\s+RunAs\b/i, 'Start-Process -Verb RunAs (elevation) blocked'],
  [/\bConvertFrom-SecureString\b/i, 'ConvertFrom-SecureString blocked -- possible credential export'],
  [/comsvcs\.dll\b[^;|]*MiniDump/i, 'lsass MiniDump blocked -- credential theft'],
];

// cmd.exe-specific deny patterns. Anchored to cmd syntax (slash-flags, drive
// letters, Windows tool names) so they do not match ordinary bash commands.
const CMD_DENY_PATTERNS = [
  [/\b(del|erase)\b[^;&|]*\/[sS]\b/i, 'cmd del /s blocked -- recursive delete'],
  [/\b(rd|rmdir)\b[^;&|]*\/[sS]\b/i, 'cmd rmdir /s blocked -- recursive directory delete'],
  [/^\s*format\s+[A-Za-z]:/i, 'cmd format blocked'],
  [/\bvssadmin\b[^;&|]*delete\s+shadows/i, 'vssadmin delete shadows blocked -- ransomware behavior'],
  [/\bwbadmin\b[^;&|]*delete\b/i, 'wbadmin delete blocked'],
  [/\bbcdedit\b/i, 'bcdedit blocked -- boot configuration tampering'],
  [/\breg\s+(add|delete)\b[^;&|]*\\(Run|RunOnce)\b/i, 'reg add to Run key blocked -- possible persistence'],
  [/\breg\s+(add|delete)\b[^;&|]*HKLM\b/i, 'reg add/delete on HKLM blocked'],
  [/\bschtasks\b[^;&|]*\/create\b/i, 'schtasks /create blocked -- possible persistence'],
  [/^\s*sc(\.exe)?\s+(create|config)\b/i, 'sc create/config blocked -- service persistence'],
  [/\bnet\s+user\b[^;&|]*\/add\b/i, 'net user /add blocked -- account creation'],
  [/\bnet\s+localgroup\s+administrators\b[^;&|]*\/add\b/i, 'Adding to administrators group blocked'],
  [/\bnetsh\s+advfirewall\b/i, 'netsh advfirewall blocked -- firewall tampering'],
  [/\btakeown\b/i, 'takeown blocked -- ownership tampering'],
  [/\bicacls\b[^;&|]*\/grant\b/i, 'icacls /grant blocked -- ACL tampering'],
  [/\bcertutil\b[^;&|]*-(urlcache|decode|decodehex)\b/i, 'certutil download/decode (LOLBin) blocked'],
  [/\bbitsadmin\b[^;&|]*\/transfer\b/i, 'bitsadmin /transfer blocked -- download'],
  [/\bmshta\b/i, 'mshta blocked -- LOLBin script execution'],
  [/\bregsvr32\b[^;&|]*\/i\b/i, 'regsvr32 /i blocked -- LOLBin'],
  [/\brundll32\b/i, 'rundll32 blocked -- LOLBin'],
  [/\bwmic\b[^;&|]*process\s+call\s+create\b/i, 'wmic process call create blocked'],
];

const APPROVE_PATTERNS = [
  // Read-only git
  /^\s*git\s+(-C\s+\S+\s+)?(status|log|diff|show|branch|tag|remote|describe|rev-parse|ls-files|shortlog|stash\s+list|blame|reflog|bisect|show-ref|cat-file|ls-tree|range-diff|whatchanged|notes\s+(list|show))\b/,
  // Safe git writes
  /^\s*git\s+(-C\s+\S+\s+)?(add|commit|fetch|checkout\s+-b|stash\s+(save|push|pop|apply|drop)|switch|pull|merge|cherry-pick|worktree\s+(list|add|remove)|restore\s+--staged)\b/,
  // Git resume operations
  /^\s*git\s+(-C\s+\S+\s+)?(rebase|cherry-pick|merge|am|revert)\s+(--continue|--abort|--skip|--quit|--edit-todo)\b/,
  // Git rebase non-interactive
  /^\s*git\s+(-C\s+\S+\s+)?rebase\s+(?!-i\b)(?!--interactive\b)/,

  // Safe system commands
  /^\s*(cd|ls|pwd|which|whoami|date|uname|file|stat|wc|id|groups|echo|cat|head|tail|realpath|basename|dirname|test|true|false|mkdir|touch|cp|mv|ln|find|sort|uniq|tr|cut|paste|tee|xargs|diff|comm|seq|printf|tput|clear|tree|less|more|column|expand|fmt|fold|join|nl|od|rev|shuf|split|tac|tsort|yes|grep|rg|awk|sed|jq|yq|fd|bat|delta|hexdump|xxd|md5sum|sha1sum|sha256sum|sha512sum|cksum|crc32)\b/,
  // Read-only system inspection
  /^\s*(ss|ps|netstat|lsof|df|du|free|uptime|top|htop|vmstat|iostat|nproc|hostname|ifconfig|ip\s+(addr|route|link|-s|-br)|ping|dig|nslookup|traceroute|env|printenv|locale|timedatectl|journalctl|systemctl\s+(status|list-units|list-unit-files|cat|show)|dmesg|lscpu|lsblk|lspci|lsusb|mount|findmnt|pgrep|pidof)\b/,
  // HTTP requests (deny rules cover dangerous flags)
  /^\s*(curl|wget)\b/,
  // Version checks
  /^\s*(cargo|npm|yarn|pnpm|uv|pip|pip3|go|rustc|gcc|node|python[23]?|ruby|java|dotnet|mvn|docker|kubectl|terraform|helm|gh|bun|deno|tsc|eslint|prettier)\s+(--version|-v(ersion)?|version)\b/,

  // Build / test
  /^\s*cargo\s+(build|test|check|clippy|fmt|doc|run|tree|metadata)\b/,
  /^\s*npm\s+(run|test|ci)\b/,
  /^\s*make(\s+(all|build|test|check|lint|fmt|debug|release|help|tidy|format))?\s*$/,
  /^\s*uv\s+(run|sync|lock|tree|pip\s+(list|show|tree))\b/,

  // Java / Maven
  /^\s*mvn\s+(clean|compile|test|install|package|verify|dependency:tree|dependency:resolve|help:effective-pom)\b/,
  /^\s*(java|javac)\s/,

  // Docker (read-only)
  /^\s*docker\s+(ps|images|logs|inspect|stats|top|port|version|info|context\s+(ls|show|inspect)|system\s+(info|df|events)|network\s+(ls|inspect)|volume\s+(ls|inspect)|compose\s+(ps|logs|config|top|images|version|events))\b/,

  // Python
  /^\s*python[23]?\s/,
  /^\s*pytest\b/,
  /^\s*python[23]?\s+-m\s+(pytest|unittest|black|ruff|mypy|pylint|isort|flake8|coverage|tox|build|venv|pip\s+(list|show|freeze))\b/,
  /^\s*(ruff|black|mypy|pylint|pyright|isort|flake8|bandit|pyflakes|autopep8|yapf|pycodestyle|pydocstyle|pyupgrade)\b/,

  // Go
  /^\s*go\s+(version|env|run|test|build|vet|fmt|generate|list|doc|mod\s+(tidy|download|verify|graph|why|init))\b/,

  // JavaScript / TypeScript tooling
  /^\s*(tsc|eslint|prettier|vitest|jest|mocha|biome|stylelint|tsx|ts-node|swc)\b/,
  /^\s*(npx|pnpm|yarn|bun)\s+(tsc|eslint|prettier|vitest|jest|mocha|biome|stylelint)\b/,
  /^\s*pnpm\s+(run|test|build|dev|lint|format|exec|start)\b/,
  /^\s*bun\s+(run|test|build|dev|x\s+\S+|start)\b/,
  /^\s*yarn\s+(run|test|build|dev|lint|format|start)\b/,

  // GitHub CLI (read-only)
  /^\s*gh\s+(auth\s+status|repo\s+(view|list)|pr\s+(view|list|status|checks|diff)|issue\s+(view|list|status)|run\s+(view|list|watch)|workflow\s+(view|list)|release\s+(view|list)|api\s+-X\s+GET\b|api\s+\/?[A-Za-z0-9_\/-]+\s*$|search\s+(repos|issues|prs|code|commits|users))\b/,

  // Kubernetes (read-only)
  /^\s*kubectl\s+(get|describe|logs|explain|top|version|api-resources|api-versions|cluster-info|config\s+(view|current-context|get-contexts|get-clusters|get-users)|auth\s+can-i)\b/,

  // Terraform / Helm (read-only)
  /^\s*terraform\s+(plan|validate|fmt|version|providers|output|state\s+(list|show)|workspace\s+(list|show)|graph)\b/,
  /^\s*helm\s+(lint|template|version|list|status|history|show\s+\w+|repo\s+(list|update)|search\s+\w+)\b/,

  // Pre-commit / linters
  /^\s*pre-commit\s+(run|install|autoupdate|validate-config|migrate-config|sample-config)\b/,
  /^\s*(tflint|shellcheck|hadolint|yamllint|markdownlint)\b/,

  // Shell control flow / builtins
  /^\s*(for|while|until|do|done|if|then|else|elif|fi|case|esac|select)\b/,
  /^\s*do\s/,
  /^\s*done\s*$/,
  /^\s*then\s*$/,
  /^\s*fi\s*$/,
  /^\s*(source|export|set|type|command|hash|builtin|timeout|time|trap|read|local|declare|readonly|unset)\s/,
  /^\s*command\s+-v\s/,
  /^\s*type\s+-[apt]/,

  // Multiplexers / archives / perms
  /^\s*(tmux|screen)\s/,
  /^\s*(tar|zip|unzip|gzip|gunzip|bzip2|xz|zstd|7z)\s/,
  /^\s*(chmod|chown)\s/,
];

// PowerShell read-only auto-approves. Conservative: only inspection cmdlets and
// their canonical aliases. Deny patterns (incl. cross-platform + PS/cmd) run
// first, so an approve here can never override a deny. Note: the bash-only
// `curl|wget` approve is intentionally NOT here -- on PowerShell those are
// aliases for Invoke-WebRequest and are gated by POSH_DENY instead.
const POSH_APPROVE_PATTERNS = [
  // Read-only verb-noun cmdlets.
  /^\s*(Get|Select|Where|ForEach|Sort|Measure|Format|Compare|Group|Out|Write|Resolve|Split|Join|Test|ConvertTo|ConvertFrom)-[A-Za-z]+\b/i,
  // Canonical read-only aliases.
  /^\s*(gci|gc|gci|ls|dir|cat|type|pwd|gl|gi|gm|gps|gsv|select|where|sort|measure|echo|cls|clear|fl|ft|fw|sls)\b/i,
  // Navigation / harmless builtins.
  /^\s*(cd|Set-Location|Push-Location|Pop-Location)\b/i,
  // Version / environment introspection.
  /^\s*\$PSVersionTable\b/i,
  /^\s*(Get-Command|gcm|Get-Help|help|Get-Member)\b/i,
  // Read-only git / tool version checks reuse the same shapes as bash.
  /^\s*git\s+(status|log|diff|show|branch|tag|remote|describe|rev-parse|ls-files|blame|reflog)\b/,
];

function checkSegmentDeny(seg, depth) {
  if (depth === undefined) depth = 0;
  if (depth > 6) return;

  const stripped = seg.replace(/^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');

  for (const [pattern, reason] of DENY_PATTERNS) {
    if (pattern.test(seg) || pattern.test(stripped)) {
      deny(reason, seg);
    }
  }
  // PowerShell + cmd deny patterns are anchored to their own syntax, so they are
  // safe to evaluate on both tools (and catch Windows tools shelled out from bash).
  for (const [pattern, reason] of POSH_DENY_PATTERNS) {
    if (pattern.test(seg) || pattern.test(stripped)) {
      deny(reason, seg);
    }
  }
  for (const [pattern, reason] of CMD_DENY_PATTERNS) {
    if (pattern.test(seg) || pattern.test(stripped)) {
      deny(reason, seg);
    }
  }

  const poshC = parsePoshInvocation(seg);
  if (poshC && poshC.innerCmd) {
    const innerSegs = splitPoshSegments(poshC.innerCmd);
    for (const inner of innerSegs) {
      checkSegmentDeny(inner, depth + 1);
    }
  }

  const cmdC = parseCmdInvocation(seg);
  if (cmdC && cmdC.innerCmd) {
    const innerSegs = splitChainSegments(cmdC.innerCmd);
    for (const inner of innerSegs) {
      checkSegmentDeny(inner, depth + 1);
    }
  }

  const shellC = parseShellCInvocation(seg);
  if (shellC) {
    if (shellC.opaque) {
      deny('Opaque shell -c argument blocked -- contains $(...), backticks, or $VAR', seg);
    }
    const innerSegs = splitChainSegments(shellC.innerCmd);
    for (const inner of innerSegs) {
      checkSegmentDeny(inner, depth + 1);
    }
  }

  const findCmds = parseFindExec(seg);
  if (findCmds) {
    for (const cmd of findCmds) {
      const innerSegs = splitChainSegments(cmd);
      for (const inner of innerSegs) {
        checkSegmentDeny(inner, depth + 1);
      }
    }
  }

  const xargsCmd = parseXargs(seg);
  if (xargsCmd) {
    const innerSegs = splitChainSegments(xargsCmd);
    for (const inner of innerSegs) {
      checkSegmentDeny(inner, depth + 1);
    }
  }

  const psubs = extractProcessSubstitutions(seg);
  for (const inner of psubs) {
    const innerSegs = splitChainSegments(inner);
    for (const innerSeg of innerSegs) {
      checkSegmentDeny(innerSeg, depth + 1);
    }
  }
}

function checkSegmentApprove(seg, depth, isPosh) {
  if (depth === undefined) depth = 0;
  if (depth > 6) return false;

  // PowerShell tool: only the conservative PS read-only set auto-approves.
  // The Unix approve set (incl. the bash `curl|wget` rule) never runs here.
  if (isPosh) {
    for (const pattern of POSH_APPROVE_PATTERNS) {
      if (pattern.test(seg)) return true;
    }
    return false;
  }

  const shellC = parseShellCInvocation(seg);
  if (shellC) {
    if (shellC.opaque) return false;
    const innerSegs = splitChainSegments(shellC.innerCmd);
    if (innerSegs.length === 0) return false;
    for (const inner of innerSegs) {
      if (!checkSegmentApprove(inner, depth + 1)) return false;
    }
    return true;
  }

  const assignMatch = seg.match(/^\s*[A-Za-z_][A-Za-z0-9_]*=(.*)$/);
  if (assignMatch) {
    const value = assignMatch[1].trim();
    if (value === '') return true;
    if (!value.includes('$(') && !value.includes('`')) return true;

    if (value.startsWith('$(')) {
      const r = extractParenContent(value, 1);
      if (r && r.end === value.length) {
        const innerSegs = splitChainSegments(r.inner);
        for (const s of innerSegs) {
          if (!checkSegmentApprove(s, depth + 1)) return false;
        }
        return true;
      }
    }
    if (value.startsWith('"$(') && value.endsWith(')"')) {
      const r = extractParenContent(value, 2);
      if (r && r.end === value.length - 1) {
        const innerSegs = splitChainSegments(r.inner);
        for (const s of innerSegs) {
          if (!checkSegmentApprove(s, depth + 1)) return false;
        }
        return true;
      }
    }
    if (value.startsWith('`') && value.endsWith('`') && value.length > 2) {
      const innerSegs = splitChainSegments(value.slice(1, -1));
      for (const s of innerSegs) {
        if (!checkSegmentApprove(s, depth + 1)) return false;
      }
      return true;
    }
  }

  const stripped = seg.replace(/^\s*([A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');
  for (const pattern of APPROVE_PATTERNS) {
    if (pattern.test(seg) || pattern.test(stripped)) {
      return true;
    }
  }
  return false;
}

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { data += chunk; });
process.stdin.on('end', () => {
  let input;
  try {
    input = JSON.parse(data);
  } catch {
    process.exit(0);
  }

  const rawCmd = input?.tool_input?.command;
  if (!rawCmd) process.exit(0);

  const isPosh = input?.tool_name === 'PowerShell';

  const cmd = normalizeUnicode(rawCmd);
  const flat = cmd.replace(/\n/g, ' ; ');
  const segments = isPosh ? splitPoshSegments(flat) : splitChainSegments(flat);

  if (segments.length === 0) process.exit(0);

  for (const seg of segments) {
    checkSegmentDeny(seg);
  }

  let allApproved = true;
  for (const seg of segments) {
    if (!checkSegmentApprove(seg, 0, isPosh)) {
      allApproved = false;
      break;
    }
  }

  if (allApproved) {
    approve(rawCmd);
  }

  audit('fallthrough', '', rawCmd);
  process.exit(0);
});
