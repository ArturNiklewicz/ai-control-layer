"""stdio MCP proxy: agent <-> guard <-> MCP server.

  .mcp.json: {"command": "uv", "args": ["run", "python", "-m", "src.guard.mcp_proxy",
              "--server", "serena", "--", "<real server command>", ...]}

Input side:  tools/call checked against mcp.allow (same patterns as the hook), path args kept
             in the repo, arguments carrying `block` PII kinds refused.
Output side: tools/list filtered to allowed tools; tools/call results screened for injection
             signatures and PII. PII is anonymized only under a valid consent grant;
             without one the content is withheld (fail closed).
ponytail: outputs are anonymized, not pseudonymized — pseudonyms would need a vault write per
call; add when an agent must de-reference tool output later.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from src.guard import audit
from src.guard.commands import check_path, decide_tool
from src.guard.injection import Signature, load_feed, scan, worst
from src.guard.pii import detect
from src.guard.policy import Policy, load
from src.guard.scrub import Blocked, NoConsent, as_anonymize, scrub
from src.result import Err, Ok

PATH_KEYS = ("path", "relative_path", "file_path", "root", "directory")


@dataclass
class Ctx:
    server: str
    agent: str
    root: Path
    policy: Callable[[], Policy | None]  # re-read per call: policy edits apply live
    feed: Callable[[], tuple[Signature, ...]]
    consented: Callable[[str], bool]
    pending: dict = field(default_factory=dict)  # request id -> "call" | "list"


def rpc_result(msg_id, text: str) -> dict:
    # a tool-level error: the model sees why, the session continues
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return []


def on_request(msg: dict, ctx: Ctx) -> tuple[dict | None, dict | None, dict | None]:
    """-> (forward to server, reply to client, audit event)."""
    method, msg_id = msg.get("method"), msg.get("id")
    if method == "tools/list":
        ctx.pending[msg_id] = "list"
        return msg, None, None
    if method != "tools/call":
        return msg, None, None
    params = msg.get("params") or {}
    tool = f"mcp__{ctx.server}__{params.get('name', '')}"
    args = params.get("arguments") or {}
    event = {"event": "mcp", "agent": ctx.agent, "tool": tool}
    policy = ctx.policy()
    agent = policy.agents.get(ctx.agent) if policy else None
    if policy is None or agent is None:
        rule, reason = (
            "policy-or-agent-invalid",
            "guard policy invalid or unknown agent",
        )
    else:
        d = decide_tool(tool, {}, ctx.root, ctx.root, policy, agent)
        for key in PATH_KEYS:
            if d.verdict == "allow" and isinstance(args.get(key), str):
                d = check_path(args[key], ctx.root, ctx.root, policy)
        blocked = sorted(
            {
                s.kind
                for t in strings(args)
                for s in detect(t)
                if policy.action(s.kind) == "block"
            }
        )
        if d.verdict == "allow" and blocked:
            rule, reason = "pii-args", f"arguments contain {', '.join(blocked)}"
        elif d.verdict == "allow":
            ctx.pending[msg_id] = "call"
            return msg, None, event | {"verdict": "allow", "rule": "ok"}
        else:
            rule, reason = d.rule, d.reason
    return (
        None,
        rpc_result(msg_id, f"[guard:{rule}] blocked: {reason}"),
        event | {"verdict": "deny", "rule": rule},
    )


def on_response(msg: dict, ctx: Ctx) -> tuple[dict, dict | None]:
    kind = ctx.pending.pop(msg.get("id"), None)
    policy = ctx.policy()
    result = msg.get("result")
    if kind is None or not isinstance(result, dict) or policy is None:
        return msg, None
    if kind == "list":
        agent = policy.agents.get(ctx.agent)
        tools = [
            t for t in result.get("tools", [])
            if agent and decide_tool(f"mcp__{ctx.server}__{t.get('name')}", {}, ctx.root, ctx.root, policy, agent).verdict == "allow"
        ]  # fmt: skip
        return {**msg, "result": {**result, "tools": tools}}, None
    event: dict = {
        "event": "mcp",
        "agent": ctx.agent,
        "channel": "tool_output",
        "id": msg.get("id"),
    }
    pii, sigs, content = Counter(), [], []
    for item in result.get("content", []):
        if item.get("type") != "text":
            content.append(item)
            continue
        text = item.get("text", "")
        hits = scan(text, ctx.feed()) if policy.screen_tool_output != "off" else []
        sigs += [h.id for h in hits]
        if policy.screen_tool_output == "block" and worst(hits) == "high":
            text = f"[guard:injection] content withheld: attack signature {', '.join(h.id for h in hits)}"
        else:
            spans = detect(text)
            match scrub(text, spans, as_anonymize(policy), {}, ctx.consented):
                case Ok(done):
                    text = done.text
                    pii.update(done.counts)
                case Err(Blocked(kinds)):
                    text = f"[guard:pii-block] content withheld: contains {', '.join(kinds)}"
                    pii.update(kinds)
                case Err(NoConsent(_, kinds)):
                    text = f"[guard:no-consent] content withheld: contains {', '.join(kinds)}; the user must run `guard login`"
                    pii.update(kinds)
        content.append({**item, "text": text})
    event |= (
        {"verdict": "allow", "rule": "ok"}
        | ({"pii": dict(pii)} if pii else {})
        | ({"signatures": sigs} if sigs else {})
    )
    return {**msg, "result": {**result, "content": content}}, event


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--server", required=True, help="name used in mcp__<server>__<tool>"
    )
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd[:1] == ["--"] else a.cmd
    root = Path(os.path.realpath(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()))
    policy_path = Path(os.environ.get("GUARD_POLICY") or root / "src/guard/policy.toml")

    def policy() -> Policy | None:
        r = load(policy_path)
        return r.value if isinstance(r, Ok) else None

    def feed() -> tuple[Signature, ...]:
        p = policy()
        r = load_feed(root / p.feed_path) if p else None
        return r.value if isinstance(r, Ok) else ()

    from src.guard.cli import current_grant
    from src.guard.consent import allows

    grant = (
        current_grant()
    )  # ponytail: read once per proxy session; restart after login
    ctx = Ctx(a.server, os.environ.get("GUARD_AGENT", "default"), root, policy, feed,
              lambda act: allows(grant, act, datetime.now(UTC)))  # fmt: skip
    child = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
    )
    out_lock = threading.Lock()

    def emit(obj: dict) -> None:
        with out_lock:
            sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
            sys.stdout.flush()

    def log(event: dict | None, started: float) -> None:
        if event:
            audit.record(
                root,
                event
                | {"latency_ms": round((time.perf_counter() - started) * 1000, 2)},
                datetime.now(UTC),
            )

    def pump_server() -> None:
        assert child.stdout
        for line in child.stdout:
            started = time.perf_counter()
            try:
                msg = json.loads(line)
            except ValueError:
                continue  # servers must not print non-JSON on stdout; drop it
            out, event = on_response(msg, ctx)
            emit(out)
            log(event, started)

    pump = threading.Thread(target=pump_server, daemon=True)
    pump.start()
    assert child.stdin
    for line in sys.stdin:
        started = time.perf_counter()
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        forward, reply, event = on_request(msg, ctx)
        if forward is not None:
            child.stdin.write(json.dumps(forward) + "\n")
            child.stdin.flush()
        if reply is not None:
            emit(reply)
        log(event, started)
    child.stdin.close()
    code = child.wait()
    pump.join(timeout=5)  # flush the server's last responses before exiting
    return code


if __name__ == "__main__":
    sys.exit(main())
