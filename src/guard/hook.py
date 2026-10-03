"""Claude Code hook: `python -m src.guard.hook` for PreToolUse and UserPromptSubmit.

stdin: hook JSON. stdout: a deny/ask/block decision, or nothing (= no objection; the normal
permission flow still applies — the guard never grants). Every decision is audited.
Any internal failure denies (fail closed): a crashing hook must not open the gate.
"""

import json
import os
import sys
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from src.guard import audit
from src.guard.commands import Decision, decide_tool, deny, tokenize
from src.guard.injection import load_feed, scan, worst
from src.guard.pii import detect
from src.guard.policy import Policy, Screen, load
from src.result import Err, Ok

MAX_SCAN = (
    2_000_000  # bytes; bigger files are not content-scanned (path rules still apply)
)


def summary(counts: Mapping[str, int]) -> str:
    return ", ".join(f"{k}×{n}" for k, n in sorted(counts.items()))


def pii_counts(text: str, policy: Policy) -> dict[str, int]:
    return dict(Counter(s.kind for s in detect(text) if policy.action(s.kind) != "off"))


def screen(
    text: str, how: Screen, feed, where: str
) -> tuple[Decision | None, list[str]]:
    if how == "off":
        return None, []
    hits = scan(text, feed)
    ids = [h.id for h in hits]
    if how == "block" and worst(hits) == "high":
        return deny(
            "injection",
            f"{where}: attack signature {', '.join(ids)} (untrusted content)",
        ), ids
    return None, ids


def read_targets(tool: str, tool_input: Mapping, cwd: Path) -> list[Path]:
    if tool == "Read":
        return [cwd / str(tool_input.get("file_path", ""))]
    if tool == "Bash":
        toks = tokenize(str(tool_input.get("command", ""))) or []
        return [p for t in toks if (p := cwd / t).is_file()]
    return []


def content_checks(
    tool: str, tool_input: Mapping, cwd: Path, policy: Policy, feed
) -> tuple[Decision | None, dict]:
    """Input side: what the agent is about to read (PII, injection) or write (blocked kinds)."""
    info: dict = {}
    for path in read_targets(tool, tool_input, cwd):
        try:
            if path.stat().st_size > MAX_SCAN:
                continue
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue  # binary / unreadable: path rules already applied
        if policy.scan_reads and (counts := pii_counts(text, policy)):
            info["pii"] = counts
            return deny(
                "pii-read",
                f"{path.name} contains personal data ({summary(counts)}). Do not try to work around "
                "this. Ask the user for an anonymized copy (only a human can authorize it).",
            ), info
        d, ids = screen(text, policy.screen_reads, feed, path.name)
        if ids:
            info["signatures"] = ids
        if d:
            return d, info
    written = " ".join(
        str(tool_input.get(k, "")) for k in ("content", "new_string", "new_source")
    )
    if blocked := sorted(
        {s.kind for s in detect(written) if policy.action(s.kind) == "block"}
    ):
        info["pii"] = dict(Counter(blocked))
        return deny(
            "pii-write", f"refusing to write {', '.join(blocked)} into files"
        ), info
    return None, info


def evaluate_prompt(
    prompt: str, policy: Policy, feed, base: dict
) -> tuple[dict | None, dict]:
    """Input side for the human's prompt. It cannot be rewritten here, only stopped."""
    info = dict(base, channel="user_prompt")
    if counts := pii_counts(prompt, policy):
        info |= {"verdict": "deny", "rule": "pii-prompt", "pii": counts}
        reason = (
            f"Prompt contains personal data ({summary(counts)}). Nothing was sent. "
            "Pseudonymize it first: `uv run python -m src.guard.cli login`, "
            "then `... pseudonymize`."
        )
        return {"decision": "block", "reason": reason}, info
    if isinstance(feed, Ok):
        d, ids = screen(prompt, policy.screen_prompt, feed.value, "prompt")
        info |= {"signatures": ids} if ids else {}
        if d:
            out = {"decision": "block", "reason": d.reason}
            return out, info | {"verdict": "deny", "rule": d.rule}
    return None, info | {"verdict": "allow", "rule": "ok"}


def evaluate(
    payload: Mapping, policy: Policy, root: Path, env: Mapping[str, str]
) -> tuple[dict | None, dict]:
    """Pure-ish core (reads files it inspects). Returns (stdout JSON or None, audit fields)."""
    event = payload.get("hook_event_name", "PreToolUse")
    agent_name = str(payload.get("agent_type") or env.get("GUARD_AGENT") or "default")
    agent = policy.agents.get(agent_name)
    cwd = Path(os.path.realpath(payload.get("cwd") or root))
    feed = load_feed(root / policy.feed_path)
    base = {"event": event, "agent": agent_name}

    if event == "UserPromptSubmit":
        out, info = evaluate_prompt(str(payload.get("prompt", "")), policy, feed, base)
        if out and policy.mode == "monitor":
            return None, info | {"verdict": "allow", "would": "deny"}
        return out, info

    tool, tool_input = (
        str(payload.get("tool_name", "")),
        payload.get("tool_input") or {},
    )
    info = dict(base, tool=tool)
    if agent is None:
        d = deny("unknown-agent", f"identity {agent_name!r} has no [agents] entry")
    elif isinstance(feed, Err):
        d = deny("feed-invalid", feed.error.detail)
    else:
        d = decide_tool(tool, tool_input, cwd, root, policy, agent)
        if d.verdict != "deny":
            c, extra = content_checks(tool, tool_input, cwd, policy, feed.value)
            info |= extra
            d = c or d
    info |= {"verdict": d.verdict, "rule": d.rule}
    if d.verdict == "allow":
        return None, info
    if policy.mode == "monitor":
        return None, info | {"verdict": "allow", "would": d.verdict}
    out = {
        "hookEventName": "PreToolUse",
        "permissionDecision": d.verdict,
        "permissionDecisionReason": f"[guard:{d.rule}] {d.reason}",
    }
    return {"hookSpecificOutput": out}, info


def self_protected(policy: Policy, policy_path: Path, root: Path) -> Policy:
    """The active policy and signature feed are never writable/readable by the agent,
    wherever they live: a guard whose rules the agent can edit guards nothing."""
    own = [Path(os.path.realpath(p)) for p in (policy_path, root / policy.feed_path)]
    rel = [p.relative_to(root).as_posix() for p in own if p.is_relative_to(root)]
    return replace(policy, deny_paths=policy.deny_paths + tuple(rel))


def main() -> int:
    started = time.perf_counter()
    env = os.environ
    root = Path(os.path.realpath(env.get("CLAUDE_PROJECT_DIR") or os.getcwd()))
    try:
        payload = json.load(sys.stdin)
        policy_path = Path(env.get("GUARD_POLICY") or root / "src/guard/policy.toml")
        match load(policy_path):
            case Ok(policy):
                policy = self_protected(policy, policy_path, root)
                out, info = evaluate(payload, policy, root, env)
            case Err(e):
                out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                       "permissionDecisionReason": f"[guard:policy-invalid] {e.detail}"}}  # fmt: skip
                if payload.get("hook_event_name") == "UserPromptSubmit":
                    out = {
                        "decision": "block",
                        "reason": f"[guard:policy-invalid] {e.detail}",
                    }
                info = {
                    "event": payload.get("hook_event_name"),
                    "verdict": "deny",
                    "rule": "policy-invalid",
                }
    except Exception as e:  # noqa: BLE001 — the one place a bug must turn into "deny"
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
               "permissionDecisionReason": f"[guard:internal-error] {type(e).__name__}"}}  # fmt: skip
        info: dict = {"verdict": "deny", "rule": "internal-error", "error": type(e).__name__}
    info["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    try:
        audit.record(root, info, datetime.now(UTC))
    except OSError:
        pass  # audit failure must not flip a deny into a crash (= allow)
    if out:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
