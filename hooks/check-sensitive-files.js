#!/usr/bin/env node
// PreToolUse hook for Read, Edit, Write, Glob, Grep tools.
// Blocks access to sensitive files and detects prompt injection in written content.
//
// Protocol:
//   stdin:  JSON with .tool_name, .tool_input
//   stdout: JSON with .hookSpecificOutput.permissionDecision = allow|deny|ask
//   exit 0: structured decision (or fallthrough if no output)
//   exit 2: hard block (stderr shown to user)

'use strict';

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

// --- PROMPT INJECTION PATTERNS ---
// Checked against content being written via Write or Edit tools.

const INJECTION_PATTERNS = [
  [/ignore\s+(all\s+)?previous\s+instructions/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/forget\s+(all\s+)?your\s+(previous\s+)?instructions/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/disregard\s+(all\s+)?prior/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/override\s+system\s+prompt/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/new\s+system\s+prompt/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/act\s+as\s+if\s+you\s+are/i,
    'Prompt injection detected -- contains instruction override pattern'],
  [/you\s+are\s+now\s+a/i,
    'Prompt injection detected -- contains role hijacking pattern'],
];

const HTML_INJECTION_PATTERN = /<!--\s*(system|instruction|prompt|ignore|override|you\s+are|act\s+as)/i;
const ENCODED_EVAL_PATTERN = /(eval|exec)\s*\(\s*(base64|atob|Buffer\.from)\s*\(/i;

// Polyglot: shell command substitution in data files (NOT markdown)
const POLYGLOT_EXTENSIONS = /\.(json|yaml|yml|xml|csv|txt|toml|ini|cfg)$/i;
const POLYGLOT_PATTERN = /(\$\(|`)\s*(curl|wget|bash|sh|nc|python|perl|ruby)\b/i;

// --- SENSITIVE FILE PATTERNS ---

const SENSITIVE_EXTENSIONS = /\.(env|pem|key|crt|p12|pfx|jks|keystore|secret|credentials|pgpass|netrc)\b/i;
const SENSITIVE_DIRS = /(^|\/)(\.ssh|\.gnupg|\.aws|\.gcloud|\.azure|\.kube|\.docker\/config|id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys)(\/|$)/i;
const ENV_FILE = /(^|\/)\.env(\.[a-zA-Z0-9_]+)?$/i;
const SECRETS_DIR = /(^|\/)(secrets?|credentials?|private[_-]?keys?)(\/|$)/i;
const SENSITIVE_GLOB = /\*\.(env|pem|key|crt|secret)/i;

// Grep secret search: only block when extracting literal values (not variable patterns)
const GREP_SECRET_EXTRACTION = /(password|secret|api.?key|token|credential|private.?key)\s*[:=]\s*[^${\s]/i;

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

  const tool = input?.tool_name || '';

  // --- Content injection checks for Write and Edit ---
  if (tool === 'Write' || tool === 'Edit') {
    const content = tool === 'Write'
      ? (input?.tool_input?.content || '')
      : (input?.tool_input?.new_string || '');

    if (content) {
      const flat = content.replace(/\n/g, ' ');

      for (const [pattern, reason] of INJECTION_PATTERNS) {
        if (pattern.test(flat)) {
          deny(reason);
        }
      }

      if (HTML_INJECTION_PATTERN.test(flat)) {
        deny('Possible prompt injection in HTML comment');
      }

      if (ENCODED_EVAL_PATTERN.test(flat)) {
        deny('Encoded eval/exec pattern in file content blocked');
      }

      // Polyglot check (data files only, not markdown)
      const filePath = input?.tool_input?.file_path || '';
      if (POLYGLOT_EXTENSIONS.test(filePath) && POLYGLOT_PATTERN.test(flat)) {
        deny('Shell command substitution in data file blocked');
      }
    }
  }

  // --- Extract path based on tool type ---
  let filePath = '';

  switch (tool) {
    case 'Read':
    case 'Edit':
    case 'Write':
      filePath = input?.tool_input?.file_path || '';
      break;
    case 'Glob': {
      const pattern = input?.tool_input?.pattern || '';
      const dir = input?.tool_input?.path || '';
      filePath = dir ? `${dir}/${pattern}` : pattern;
      break;
    }
    case 'Grep': {
      filePath = input?.tool_input?.path || '';
      // Check if searching for secret values
      const searchPattern = input?.tool_input?.pattern || '';
      if (GREP_SECRET_EXTRACTION.test(searchPattern)) {
        deny('Searching for secret values in code is blocked');
      }
      break;
    }
  }

  if (!filePath) process.exit(0);

  // --- Sensitive file checks ---

  if (SENSITIVE_EXTENSIONS.test(filePath)) {
    deny('Access to sensitive file blocked: matches sensitive extension pattern');
  }

  if (SENSITIVE_DIRS.test(filePath)) {
    deny('Access to sensitive directory/file blocked');
  }

  if (ENV_FILE.test(filePath)) {
    deny('Access to .env file blocked');
  }

  if (SECRETS_DIR.test(filePath)) {
    deny('Access to secrets/credentials directory blocked');
  }

  if (tool === 'Glob' && SENSITIVE_GLOB.test(filePath)) {
    deny('Glob pattern targeting sensitive files blocked');
  }

  // Fallthrough
  process.exit(0);
});
