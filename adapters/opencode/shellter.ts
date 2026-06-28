// shellter — opencode adapter.
//
// Routes opencode tool calls through shellter's existing hooks (one shared
// detector for every client). On `tool.execute.before` it reshapes the call
// into shellter's stdin JSON, spawns check-bash.js / check-sensitive-files.js,
// and throws to block when the decision is deny or ask.
//
// Install: drop this file in ~/.config/opencode/plugin/ and put shellter's
// hooks/ next to it as ../shellter-hooks/ (or set SHELLTER_HOOKS_DIR).
import { execFileSync } from "node:child_process";
import { existsSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOKS =
  process.env.SHELLTER_HOOKS_DIR ||
  [
    join(HERE, "..", "shellter-hooks"), // installed: plugin/../shellter-hooks
    join(HERE, "..", "..", "hooks"),    // dev: adapters/opencode/../../hooks
    join(HERE, "shellter-hooks"),
  ].find((d) => existsSync(d)) ||
  join(HERE, "..", "shellter-hooks");

const BASH_HOOK = join(HOOKS, "check-bash.js");
const FILE_HOOK = join(HOOKS, "check-sensitive-files.js");
const DEBUG = !!process.env.SHELLTER_DEBUG;

function dbg(o) {
  if (!DEBUG) return;
  try { appendFileSync(join(HERE, "shellter-debug.log"), JSON.stringify(o) + "\n"); } catch {}
}

// opencode tool name -> shellter hook + Claude-Code-shaped input
function mapTool(tool, args) {
  const a = args || {};
  switch (tool) {
    case "bash":
      // opencode's bash tool runs PowerShell on Windows -- map to PowerShell there
      // so PS segmentation + approve rules apply (deny rules run cross-tool anyway).
      return { hook: BASH_HOOK, name: process.platform === "win32" ? "PowerShell" : "Bash", input: { command: a.command ?? "" } };
    case "read":
      return { hook: FILE_HOOK, name: "Read", input: { file_path: a.filePath ?? a.path ?? "" } };
    case "write":
      return { hook: FILE_HOOK, name: "Write", input: { file_path: a.filePath ?? a.path ?? "", content: a.content ?? "" } };
    case "edit":
      // check-sensitive-files.js reads an Edit's new text from `new_string` -- must
      // match that key or the content/injection scan on edits is silently skipped.
      return { hook: FILE_HOOK, name: "Edit", input: { file_path: a.filePath ?? a.path ?? "", new_string: a.newString ?? a.replacement ?? a.content ?? "" } };
    case "grep":
      return { hook: FILE_HOOK, name: "Grep", input: { pattern: a.pattern ?? "", path: a.path ?? "" } };
    case "glob":
      return { hook: FILE_HOOK, name: "Glob", input: { pattern: a.pattern ?? "", path: a.path ?? "" } };
    default:
      return null;
  }
}

// Prefer node (the runtime shellter is tested under); fall back to whatever is
// running opencode (bun) so the gate still works if node isn't on PATH.
function runHook(hook, event) {
  const input = JSON.stringify(event);
  for (const exe of ["node", process.execPath]) {
    try {
      return execFileSync(exe, [hook], { input, encoding: "utf8", timeout: 5000 });
    } catch (e: any) {
      if (e && e.code === "ENOENT") continue;        // runtime missing -> try next
      if (e && e.stdout) return e.stdout.toString();  // hook printed then exited nonzero
      console.warn("[shellter] hook error:", e && e.message);
      return "";                                      // infra failure -> fail open, never brick opencode
    }
  }
  return "";
}

function decide(out) {
  try {
    const h = JSON.parse(out).hookSpecificOutput;
    return { decision: h?.permissionDecision || "allow", reason: h?.permissionDecisionReason || "" };
  } catch {
    // blank/garbled output = fallthrough = allow. Log the raw output so a
    // malformed-JSON regression (which silently disables the gate) is diagnosable.
    dbg({ event: "decide-parse-fail", raw: (out || "").slice(0, 200) });
    return { decision: "allow", reason: "" };
  }
}

export const ShellterPlugin = async ({ directory, worktree }) => {
  const cwd = directory || worktree || process.cwd();
  dbg({ event: "loaded", cwd, hooks: HOOKS });
  return {
    "tool.execute.before": async (input, output) => {
      const m = mapTool(input?.tool, output?.args);
      if (!m) return;
      const { decision, reason } = decide(runHook(m.hook, { tool_name: m.name, tool_input: m.input, cwd }));
      dbg({ tool: input?.tool, argKeys: Object.keys(output?.args || {}), decision });
      if (decision === "deny" || decision === "ask") {
        // The reason already carries the guidance (incl. any trust command for a
        // flagged script), so surface it verbatim rather than a fixed placeholder.
        throw new Error(`shellter ${decision === "ask" ? "needs your approval for" : "blocked"} this ${m.name}: ${reason}`);
      }
    },
  };
};
