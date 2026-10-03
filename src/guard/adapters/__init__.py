"""Thin harness adapters. Each maps a harness's native payload onto the Claude Code hook shape,
runs the one decision core (`hook.decide`: policy, commands, PII, signatures, audit) and maps the
verdict back. No adapter makes its own security decision.
"""

import os
from dataclasses import dataclass
from pathlib import Path

from src.guard.hook import decide


@dataclass(frozen=True, slots=True)
class Verdict:
    verdict: str  # allow | ask | deny
    rule: str
    reason: str

    @property
    def blocked(self) -> bool:
        return self.verdict == "deny"


def root_of(root: Path | str | None = None) -> Path:
    return Path(
        os.path.realpath(root or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
    )


def check(
    payload: dict,
    harness: str,
    root: Path | str | None = None,
    agent: str | None = None,
) -> Verdict:
    """payload in Claude Code hook shape (hook_event_name, tool_name, tool_input, prompt,
    tool_response). `agent` comes from the harness integration, never from the model."""
    env = dict(os.environ) | ({"GUARD_AGENT": agent} if agent else {})
    if harness != "claude-agent-sdk":  # only that SDK sets agent_type itself; elsewhere it is payload data
        payload = {k: v for k, v in payload.items() if k != "agent_type"}
    r = root_of(root)
    out, info = decide(
        payload | {"cwd": str(r / str(payload.get("cwd") or ".")), "harness": harness}, r, env  # relative cwd: from the project root
    )
    hso = (out or {}).get("hookSpecificOutput", {})
    reason = hso.get("permissionDecisionReason") or (out or {}).get("reason", "")
    verdict = hso.get("permissionDecision") or ("deny" if out else "allow")
    return Verdict(verdict, str(info.get("rule", "")), reason)


def mcp_name(server: str, tool: str) -> str:
    return f"mcp__{server}__{tool}"
