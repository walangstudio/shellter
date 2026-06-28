// shellter — pi adapter (@earendil-works/pi-coding-agent extension).
//
// Routes pi's agent tool calls through shellter's existing hooks (one shared
// detector for every client). On the `tool_call` event it reshapes the call
// into shellter's stdin JSON, spawns check-bash.js / check-sensitive-files.js,
// and returns { block: true, reason } when the decision is deny or ask.
//
// Only `tool_call` (the AGENT surface) is gated -- that is the prompt-injection
// threat model. `user_bash` (the human typing !cmd) is explicit human intent,
// not an injection vector, and pi gives it no block flag, so it is left alone.
//
// Install: drop this file at ~/.pi/agent/extensions/shellter.ts (always loaded,
// not repo-controlled) and put shellter's hooks/ next to it as
// ../shellter-hooks/  (or set SHELLTER_HOOKS_DIR).
import { execFileSync } from "node:child_process";
import { existsSync, appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const HOOKS =
  process.env.SHELLTER_HOOKS_DIR ||
  [
    join(HERE, "..", "shellter-hooks"), // installed: extensions/../shellter-hooks
    join(HERE, "..", "..", "hooks"),    // dev: adapters/pi/../../hooks
    join(HERE, "shellter-hooks"),
  ].find((d) => existsSync(d)) ||
  join(HERE, "..", "shellter-hooks");

const BASH_HOOK = join(HOOKS, "check-bash.js");
const FILE_HOOK = join(HOOKS, "check-sensitive-files.js");
const DEBUG = !!process.env.SHELLTER_DEBUG;

function dbg(o: any) {
  if (!DEBUG) return;
  try { appendFileSync(join(HERE, "shellter-debug.log"), JSON.stringify(o) + "\n"); } catch {}
}

// pi tool name -> shellter hook + Claude-Code-shaped input.
function mapTool(toolName: string, input: any) {
  const a = input || {};
  switch (toolName) {
    case "bash":
      // pi's bash runs the platform shell; on Windows that is PowerShell, so map
      // there to apply PS segmentation/approve rules (deny rules run cross-tool).
      return { hook: BASH_HOOK, name: process.platform === "win32" ? "PowerShell" : "Bash", input: { command: a.command ?? "" } };
    case "read":
      return { hook: FILE_HOOK, name: "Read", input: { file_path: a.path ?? "" } };
    case "write":
      return { hook: FILE_HOOK, name: "Write", input: { file_path: a.path ?? "", content: a.content ?? "" } };
    case "edit":
      // The attacker-influenced text on an edit is the new text. check-sensitive-files.js
      // reads it from `new_string`; join every edit's newText so the injection scan sees it.
      // pi's schema is { path, edits:[{oldText,newText}] }; the top-level fallback covers
      // an edit-like tool that delivers new text directly instead of in an edits array.
      return { hook: FILE_HOOK, name: "Edit", input: { file_path: a.path ?? "", new_string: Array.isArray(a.edits) ? a.edits.map((e: any) => e?.newText ?? "").join("\n") : (a.newText ?? a.new_string ?? a.content ?? "") } };
    case "grep":
      return { hook: FILE_HOOK, name: "Grep", input: { pattern: a.pattern ?? "", path: a.path ?? "" } };
    case "find":
      return { hook: FILE_HOOK, name: "Glob", input: { pattern: a.pattern ?? "", path: a.path ?? "" } };
    default:
      return null; // ls / custom / MCP tools: shape unknown -> don't gate (fall through)
  }
}

// Prefer node (shellter's tested runtime); fall back to whatever runs pi (bun)
// so the gate still works if node isn't on PATH.
function runHook(hook: string, event: any) {
  const input = JSON.stringify(event);
  for (const exe of ["node", process.execPath]) {
    try {
      return execFileSync(exe, [hook], { input, encoding: "utf8", timeout: 5000 });
    } catch (e: any) {
      if (e && e.code === "ENOENT") continue;        // runtime missing -> try next
      if (e && e.stdout) return e.stdout.toString();  // hook printed then exited nonzero
      console.warn("[shellter] hook error:", e && e.message);
      return "";                                      // infra failure -> fail open, never brick pi
    }
  }
  // Both node and the pi runtime failed to spawn the detector -> warn loudly
  // (still fall open) so a misconfigured hooks dir is diagnosable, not silent.
  console.warn("[shellter] detector did NOT run -- command NOT screened:", hook);
  return "";
}

function decide(out: string) {
  try {
    const h = JSON.parse(out).hookSpecificOutput;
    return { decision: h?.permissionDecision || "allow", reason: h?.permissionDecisionReason || "" };
  } catch {
    dbg({ event: "decide-parse-fail", raw: (out || "").slice(0, 200) });
    return { decision: "allow", reason: "" }; // blank/garbled = fallthrough = allow
  }
}

export default function (pi: any) {
  dbg({ event: "loaded", hooks: HOOKS });
  pi.on("tool_call", async (event: any, ctx: any) => {
    const m = mapTool(event?.toolName, event?.input);
    if (!m) return;
    const { decision, reason } = decide(runHook(m.hook, { tool_name: m.name, tool_input: m.input, cwd: ctx?.cwd || process.cwd() }));
    dbg({ tool: event?.toolName, decision });
    if (decision === "deny" || decision === "ask") {
      // reason carries the guidance (incl. any trust command); surface it verbatim.
      return { block: true, reason: `shellter ${decision === "ask" ? "needs your approval for" : "blocked"} this ${m.name}: ${reason}` };
    }
  });
}
