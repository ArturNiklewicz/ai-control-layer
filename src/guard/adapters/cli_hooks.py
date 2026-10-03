"""Command hooks for Cursor, Gemini CLI and Codex CLI: stdin JSON -> guard -> native stdout JSON.

  python -m src.guard.adapters.cli_hooks cursor|gemini|codex

Every harness here fails OPEN on a crash or non-zero exit other than 2, so the shell entry
point is `... || exit 2` (see templates/) and this module always prints a decision.
"""

import json
import os
import re
import shlex
import signal
import sys
from collections.abc import Callable

from src.guard.hook import BUDGET_S
from src.guard.adapters import Verdict, check, mcp_name

# --- Cursor (https://cursor.com/docs/agent/hooks) ---


def cursor_in(p: dict) -> dict | None:
    match p.get("hook_event_name"):
        case "beforeShellExecution":
            return {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": p.get("command")},
                "cwd": p.get("cwd"),
            }
        case "beforeMCPExecution":
            try:
                args = json.loads(
                    p.get("tool_input") or "{}"
                )  # Cursor sends a JSON string
            except ValueError:
                args = None  # malformed -> the core denies a non-object tool_input
            return {
                "hook_event_name": "PreToolUse",
                "tool_name": mcp_name(
                    str(p.get("mcp_server_name")), str(p.get("tool_name"))
                ),
                "tool_input": args,
            }
        case "beforeReadFile":
            return {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": p.get("file_path")},
            }
        case "beforeSubmitPrompt":
            return {"hook_event_name": "UserPromptSubmit", "prompt": p.get("prompt")}
        case "postToolUse" | "afterMCPExecution" | "afterShellExecution":
            return {"hook_event_name": "PostToolUse", "tool_name": str(p.get("tool_name") or "Bash"),
                    "tool_response": p.get("tool_output", p.get("result_json", p.get("output")))}  # fmt: skip
    return None


def cursor_out(p: dict, v: Verdict) -> dict:
    if p.get("hook_event_name") == "beforeSubmitPrompt":
        return (
            {"continue": not v.blocked, "user_message": v.reason}
            if v.blocked
            else {"continue": True}
        )
    if v.verdict == "allow":
        return {"permission": "allow"}
    perm = (
        "deny"
        if p.get("hook_event_name") == "beforeReadFile" and v.verdict == "ask"
        else v.verdict
    )
    return {"permission": perm, "user_message": v.reason, "agent_message": v.reason}


# --- Gemini CLI (https://geminicli.com/docs/hooks/reference/) ---

GEMINI_TOOLS = {  # gemini tool -> (Claude Code tool, {gemini arg: claude arg})
    "run_shell_command": ("Bash", {"command": "command", "directory": "cwd"}),
    "read_file": ("Read", {"absolute_path": "file_path", "file_path": "file_path"}),
    "write_file": ("Write", {"file_path": "file_path", "content": "content"}),
    "replace": (
        "Edit",
        {
            "file_path": "file_path",
            "old_string": "old_string",
            "new_string": "new_string",
        },
    ),
    "search_file_content": ("Grep", {"pattern": "pattern", "path": "path"}),
    "glob": ("Glob", {"pattern": "pattern", "path": "path"}),
    "web_fetch": ("WebFetch", {"prompt": "prompt"}),
    "google_web_search": ("WebSearch", {"query": "query"}),
}


def gemini_in(p: dict) -> dict | None:
    match p.get("hook_event_name"):
        case "BeforeAgent":
            return {"hook_event_name": "UserPromptSubmit", "prompt": p.get("prompt")}
        case "BeforeTool" | "AfterTool" as ev:
            name, args = str(p.get("tool_name")), p.get("tool_input")
            if mcp := p.get("mcp_context"):
                tool, mapped = (
                    mcp_name(
                        str(mcp.get("server_name", "")), str(mcp.get("tool_name", name))
                    ),
                    args,
                )
            elif name == "read_many_files":  # a path list: reuse the Bash read checks per path
                paths = args.get("paths") if isinstance(args, dict) else None
                ok = (  # fail closed on include/exclude/recursive and globs: only literal paths
                    isinstance(args, dict) and set(args) <= {"paths"} and isinstance(paths, list) and paths
                    and all(isinstance(x, str) and not any(c in x for c in "*?[{") for x in paths)
                )  # fmt: skip
                tool, mapped = "Bash", {"command": "cat " + shlex.join(paths) if ok else None}  # type: ignore[arg-type]
            elif name in GEMINI_TOOLS:
                tool, keys = GEMINI_TOOLS[name]
                mapped = (
                    {keys.get(k, k): v for k, v in args.items()}
                    if isinstance(args, dict)
                    else args
                )
            else:
                tool, mapped = (
                    name,
                    args,
                )  # ponytail: unknown tools still get generic path checks
            if ev == "AfterTool":
                return {
                    "hook_event_name": "PostToolUse",
                    "tool_name": tool,
                    "tool_response": p.get("tool_response"),
                }
            return {
                "hook_event_name": "PreToolUse",
                "tool_name": tool,
                "tool_input": mapped,
            }
    return None


def gemini_out(p: dict, v: Verdict) -> dict:
    # gemini has no "ask": a human-confirm rule is a deny here (fail safe)
    return {} if v.verdict == "allow" else {"decision": "deny", "reason": v.reason}


# --- Codex CLI (Claude-style hooks; https://learn.chatgpt.com/docs/hooks) ---


PATCH_PATH = re.compile(r"^\s*\*\*\*\s*(?:(?:Add|Update|Delete) File|Move to):\s*(.+?)\s*$", re.I)
PATCH_MARK = re.compile(r"^\s*\*\*\*\s*(?:Begin Patch|End Patch|End of File)\s*$", re.I)


def patch_paths(patch: str) -> list[str] | None:
    """Target paths, or None if any `***` line is not a header we understand (fail closed:
    a lenient patch applier must never see a path this parser missed)."""
    paths = []
    for line in patch.splitlines():
        if m := PATCH_PATH.match(line):
            paths.append(m[1])
        elif line.lstrip().startswith("***") and not PATCH_MARK.match(line):
            return None
    return paths or None


def codex_in(p: dict) -> list[dict] | dict | None:
    ev = p.get("hook_event_name")
    if ev not in ("PreToolUse", "PostToolUse", "UserPromptSubmit"):
        return None
    if p.get("tool_name") != "apply_patch" or ev != "PreToolUse":
        return p
    ti = p.get("tool_input")
    patch = ti.get("command") if isinstance(ti, dict) else None
    paths = patch_paths(patch) if isinstance(patch, str) else None
    if not paths:  # unparseable patch: the core denies a non-object tool_input
        return p | {"tool_name": "Write", "tool_input": None}
    # one Write per target path (path rules), each carrying the patch text (PII write rules)
    return [p | {"tool_name": "Write", "tool_input": {"file_path": f, "content": patch}} for f in paths]


def codex_out(p: dict, v: Verdict) -> dict:
    if v.verdict == "allow":
        return {}
    if p.get("hook_event_name") in ("UserPromptSubmit", "PostToolUse"):
        return {"decision": "block", "reason": v.reason}
    # codex rejects "ask" on PreToolUse (and then lets the tool run): ask -> deny
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": v.reason,
        }
    }


HARNESSES: dict[
    str, tuple[Callable[[dict], list[dict] | dict | None], Callable[[dict, Verdict], dict]]
] = {
    "cursor": (cursor_in, cursor_out),
    "gemini": (gemini_in, gemini_out),
    "codex": (codex_in, codex_out),
}


def run(harness: str, raw: str) -> dict:
    to_guard, from_guard = HARNESSES[harness]
    try:
        p = json.loads(raw)
    except ValueError:
        p = None
    if not isinstance(p, dict):
        return from_guard(
            {},
            Verdict(
                "deny", "malformed", "[guard:malformed] payload is not a JSON object"
            ),
        )
    mapped = to_guard(p)
    if (
        mapped is None
    ):  # an event we don't gate (session start, compaction...): no objection
        return {}
    verdicts = [check(m, harness) for m in (mapped if isinstance(mapped, list) else [mapped])]
    order = {"deny": 0, "ask": 1, "allow": 2}
    return from_guard(p, min(verdicts, key=lambda v: order.get(v.verdict, 0)))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in HARNESSES:
        print(f"usage: cli_hooks {'|'.join(HARNESSES)}", file=sys.stderr)
        return 2
    def expired(*_: object) -> None:  # these harnesses let the tool run on a hook timeout
        print("[guard:timeout] scan exceeded the time budget", file=sys.stderr, flush=True)
        os._exit(2)  # exit 2 = block in Cursor, Gemini and Codex

    signal.signal(signal.SIGALRM, expired)  # ponytail: POSIX only, like hook.py
    signal.alarm(int(os.environ.get("GUARD_HOOK_BUDGET_S") or BUDGET_S))
    print(json.dumps(run(args[0], sys.stdin.read())), flush=True)
    signal.alarm(0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
