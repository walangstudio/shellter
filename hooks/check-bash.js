#!/usr/bin/env node
// PreToolUse hook for Bash commands.
//
// Protocol:
//   stdin:  JSON with .tool_input.command
//   stdout: JSON with .hookSpecificOutput.permissionDecision = allow|deny|ask
//   exit 0: structured decision (or fallthrough if no output)
//   exit 2: hard block (stderr shown to user)
//
// Policy:
//   - Deny destructive commands (rm -rf system dirs, force push main, drop db, etc.)
//   - Auto-approve genuinely safe read-only commands
//   - Everything else falls through to normal permission prompt
//
// Chain handling:
//   Splits on &&, ||, ; (outside quotes/subshells) and checks each segment.
//   DENY if ANY segment matches a deny pattern.
//   APPROVE only if ALL segments match an approve pattern.

'use strict';

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

function deny(reason) {
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

function approve() {
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

// --- DENY PATTERNS ---
// Each entry: [regex, reason]
// Tested against each chain segment independently.

const DENY_PATTERNS = [
  // Encoded payload execution
  [/(base64|b64)\s*(--)?d(ecode)?\s*.*\|\s*(bash|sh|zsh|eval|python|perl|ruby|node)/i,
    'Encoded payload piped to shell blocked'],
  [/\becho\s+.*\|\s*(base64|xxd)\s.*\|\s*(bash|sh)/i,
    'Encoded execution chain blocked'],

  // eval (targeted, not blanket)
  [/^\s*eval\s/,
    'eval as command blocked -- use explicit commands instead'],
  [/\beval\s+.*(\$[({]|`)/,
    'eval with dynamic content blocked -- possible injection'],
  [/\beval\s+.*\b(base64|decode|atob)\b/i,
    'eval with encoded payload blocked'],

  // Reverse shells
  [/bash\s+-i\s+.*>\/dev\/tcp\//,
    'Reverse shell pattern blocked'],
  [/\/dev\/(tcp|udp)\//,
    'Direct /dev/tcp or /dev/udp access blocked'],
  [/\b(nc|ncat|netcat|socat)\s+.*-[a-zA-Z]*e\s/i,
    'Netcat with -e blocked -- possible reverse shell'],
  [/python[23]?\s+-c\s+.*\b(socket|pty\.spawn|subprocess)\b/i,
    'Python one-liner with socket/pty/subprocess blocked'],
  [/perl\s+-e\s+.*\bsocket\b/i,
    'Perl socket one-liner blocked'],
  [/ruby\s+-e\s+.*\bTCPSocket\b/i,
    'Ruby TCPSocket one-liner blocked'],

  // Data exfiltration
  [/\bcurl\s+.*(-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)[\s='"]/i,
    'curl with data upload blocked -- review manually'],
  [/\bwget\s+.*--post-(data|file)/i,
    'wget POST blocked -- review manually'],

  // Download-and-execute
  [/\b(curl|wget)\s+.*\|\s*(bash|sh|zsh|python|perl|ruby|node)/i,
    'Download-and-execute pipe blocked -- inspect script first'],

  // Persistence mechanisms
  [/(crontab|\/etc\/cron|\/etc\/systemd|\/etc\/init\.d|\/etc\/rc\.local)/i,
    'Modifying cron/systemd/init blocked -- possible persistence'],
  [/(>|>>|tee)\s+\/etc\//i,
    'Writing to /etc blocked'],

  // Privilege escalation
  [/^\s*sudo\s/,
    'sudo blocked -- run privileged commands manually'],
  [/\bchmod\s+[0-7]*[4-7][0-7]*[0-7]*\s+.*\.(sh|py|rb|js|pl)\b/,
    'Setting setuid/setgid on scripts blocked'],
  [/\bchmod\s+[u+]*s\b/,
    'chmod setuid/setgid blocked'],

  // Environment variable exfiltration
  [/\b(env|printenv|set)\b.*\|\s*(curl|wget|nc|netcat|ncat)/i,
    'Piping environment to network tool blocked'],

  // SSH/SCP (lateral movement)
  [/^\s*(ssh|scp|sftp)\s/,
    'SSH/SCP blocked -- run manually'],

  // Supply chain
  [/\b(pip|npm|yarn)\s+install\s+.*https?:\/\//i,
    'Installing packages from raw URLs blocked'],

  // Container escape
  [/docker\s+run\s+.*--privileged/i,
    'Privileged docker run blocked'],
  [/docker\s+run\s+.*-v\s+\/:\//i,
    'Docker host root mount blocked'],

  // Process injection
  [/\/proc\/[0-9]+\/mem|\/proc\/[0-9]+\/maps|ptrace/,
    'Process memory access blocked'],

  // Disk operations
  [/\b(mkfs|fdisk|parted)\b/i,
    'Disk/partition operations blocked'],
  [/\bdd\s+if=/i,
    'dd disk operation blocked'],

  // Firewall
  [/\b(iptables|nftables|ufw|firewall-cmd)\b/i,
    'Firewall modification blocked'],

  // Git destructive
  [/git\s+push\s+.*\b(main|master)\b/,
    'git push to main/master blocked -- push to a feature branch'],
  [/git\s+push\s+origin\s*$/,
    'git push to default branch blocked'],
  [/git\s+push\s+.*--force/,
    'git push --force blocked'],
  [/git\s+push\s+-f\b/,
    'git push -f blocked'],
  [/git\s+reset\s+--hard/,
    'git reset --hard blocked -- can destroy uncommitted work'],
  [/git\s+clean\s+-[a-zA-Z]*f/,
    'git clean -f blocked -- deletes untracked files'],
  [/git\s+checkout\s+--\s/,
    'git checkout -- blocked -- discards uncommitted changes'],

  // Sensitive file reads via shell
  [/(cat|less|more|head|tail|bat|vi|vim|nano|sed|awk|grep)\s+.*\.(env|pem|key|crt|secret|credentials|pgpass|netrc|npmrc)\b/i,
    'Reading sensitive file via shell blocked'],
  [/(cat|less|more|head|tail|bat|vi|vim|nano|sed|awk|grep)\s+.*(\.env|\.secret|credentials|id_rsa|id_ed25519|\.ssh\/|\.gnupg\/|\.aws\/|\.gcloud\/)/i,
    'Reading sensitive file/directory via shell blocked'],

  // rm on system directories (handles both rm -rf and rm -fr)
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+(\/|\/home|\/etc|\/usr|\/var|\/boot|\/sys|\/proc|\/dev)\b/,
    'Destructive rm on system directory blocked'],
  [/rm\s+-[a-zA-Z]*(?=.*r)(?=.*f)[a-zA-Z]*\s+~\b/,
    'Destructive rm on home directory blocked'],

  // SQL destructive
  [/\b(drop|truncate)\s+(database|table|schema)\b/i,
    'DROP/TRUNCATE blocked'],
];

// --- APPROVE PATTERNS ---
// Each segment must match one of these for auto-approval.

const APPROVE_PATTERNS = [
  // Read-only git
  /^\s*git\s+(status|log|diff|show|branch|tag|remote|describe|rev-parse|ls-files|shortlog|stash\s+list)\b/,
  // Safe git writes
  /^\s*git\s+(add|commit|fetch|stash\s+(save|push|pop|apply))\b/,
  // Safe system commands
  /^\s*(cd|ls|pwd|which|whoami|date|uname|file|stat|wc|id|groups|echo|cat|head|tail|realpath|basename|dirname|test|true|false|mkdir|touch|cp|mv|ln|find|sort|uniq|tr|cut|paste|tee|xargs|diff|comm|seq|printf|tput|clear|tree|less|more|column|expand|fmt|fold|join|nl|od|rev|shuf|split|tac|tsort|yes|grep|rg|awk|sed|jq|yq)\b/,
  // Read-only system inspection
  /^\s*(ss|ps|netstat|lsof|df|du|free|uptime|top|htop|vmstat|iostat|nproc|hostname|ifconfig|ip\s+(addr|route|link)|ping|dig|nslookup|traceroute|env|printenv|locale|timedatectl|journalctl|systemctl\s+status|dmesg|lscpu|lsblk|lspci|lsusb|mount|findmnt)\b/,
  // Version checks
  /^\s*(cargo|npm|yarn|pnpm|uv|pip|go|rustc|gcc|node|python3?|ruby|java|dotnet)\s+--version\s*$/,
  // Build/test (not install/publish)
  /^\s*cargo\s+(build|test|check|clippy|fmt|doc)\b/,
  /^\s*npm\s+(run|test|ci)\b/,
  /^\s*make(\s+(all|build|test|check|lint|fmt|debug|release))?\s*$/,
  /^\s*uv\s+run\b/,
];

function checkDeny(segment) {
  for (const [pattern, reason] of DENY_PATTERNS) {
    if (pattern.test(segment)) {
      deny(reason);
    }
  }
}

function checkApprove(segment) {
  for (const pattern of APPROVE_PATTERNS) {
    if (pattern.test(segment)) {
      return true;
    }
  }
  return false;
}

// --- MAIN ---

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

  const cmd = input?.tool_input?.command;
  if (!cmd) process.exit(0);

  const flat = cmd.replace(/\n/g, ' ; ');
  const segments = splitChainSegments(flat);

  if (segments.length === 0) process.exit(0);

  // Deny phase: any segment triggers deny for the whole command
  for (const seg of segments) {
    checkDeny(seg);
  }

  // Approve phase: all segments must match for auto-approval
  let allApproved = true;
  for (const seg of segments) {
    if (!checkApprove(seg)) {
      allApproved = false;
      break;
    }
  }

  if (allApproved) {
    approve();
  }

  // Fallthrough: normal permission prompt
  process.exit(0);
});
