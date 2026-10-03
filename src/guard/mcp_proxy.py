"""stdio MCP proxy: agent <-> guard <-> MCP server.

  .mcp.json: {"command": "uv", "args": ["run", "python", "-m", "src.guard.mcp_proxy",
              "--server", "serena", "--", "<real server command>", ...]}

Input side:  only initialize, ping, tools/list, tools/call and notifications/* pass; tools/call
             checked against mcp.allow (same patterns as the hook), path-like args kept in the
             repo, arguments carrying `block` PII kinds refused.
Output side: tools/list filtered to allowed tools; every string of every server message (results,
             errors, notifications) screened for injection signatures and `block` PII kinds
             (secrets, cards: withheld); server-initiated requests denied; unmatched responses
             dropped. Other personal data is not this layer's job: the result reaches the model
             as a tool_result through the anonymizing proxy (gateway.py), which pseudonymizes it.
"""

import argparse
import json
import os
import re
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
from src.result import Err, Ok

PATH_KEYS = ("path", "relative_path", "file_path", "root", "directory")
ALLOWED = {"initialize", "ping", "tools/list", "tools/call"}  # + notifications/* without id
NAME = re.compile(r"[A-Za-z0-9_.-]+")


@dataclass
class Ctx:
    server: str
    agent: str
    root: Path
    policy: Callable[[], Policy | None]  # re-read per call: policy edits apply live
    feed: Callable[[], tuple[Signature, ...]]
    pending: dict = field(default_factory=dict)  # json.dumps(id) -> "call" | "list" | "other"


def rpc_result(msg_id, text: str) -> dict:
    # a tool-level error: the model sees why, the session continues
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def rpc_error(msg_id, code: int, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": text}}


def usable(msg_id) -> bool:
    return isinstance(msg_id, str | int) and not isinstance(msg_id, bool)


def strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in [k, *strings(v)]]  # keys too: a model reads them
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return []


def map_strings(value, f: Callable[[str], str]):
    if isinstance(value, str):
        return f(value)
    if isinstance(value, dict):
        return {f(k): map_strings(v, f) for k, v in value.items()}
    if isinstance(value, list):
        return [map_strings(v, f) for v in value]
    return value


def deny_event(ctx: Ctx, rule: str, **extra) -> dict:
    return {"event": "mcp", "agent": ctx.agent, "verdict": "deny", "rule": rule} | extra


def on_request(msg, ctx: Ctx) -> tuple[dict | None, dict | None, dict | None]:
    """-> (forward to server, reply to client, audit event). Never raises."""
    try:
        return _request(msg, ctx)
    except Exception:  # fail closed: nothing malformed reaches the server
        mid = msg.get("id") if isinstance(msg, dict) else None
        reply = rpc_error(mid, -32603, "[guard:malformed] request rejected")
        return None, reply if usable(mid) else None, deny_event(ctx, "malformed")


def _request(msg, ctx: Ctx):
    if not isinstance(msg, dict):  # also batch arrays: removed from MCP in 2025-06
        reply = rpc_error(None, -32600, "[guard:invalid-request] single JSON objects only")
        return None, reply, deny_event(ctx, "invalid-request")
    method, msg_id = msg.get("method"), msg.get("id")
    if not isinstance(method, str):
        return None, None, deny_event(ctx, "invalid-request")
    if "id" not in msg:  # notification: only notifications/*
        if method.startswith("notifications/"):
            return msg, None, None
        return None, None, deny_event(ctx, "invalid-request", method=method[:80])
    if not usable(msg_id):
        return None, None, deny_event(ctx, "invalid-request")
    if method not in ALLOWED:
        reply = rpc_error(msg_id, -32601, "[guard:method-not-allowed] method not permitted")
        return None, reply, deny_event(ctx, "method-not-allowed", method=method[:80])
    key = json.dumps(msg_id)
    if key in ctx.pending:
        reply = rpc_error(msg_id, -32600, "[guard:duplicate-id] request id already in flight")
        return None, reply, deny_event(ctx, "duplicate-id")
    if method != "tools/call":
        ctx.pending[key] = "list" if method == "tools/list" else "other"
        return msg, None, None
    params = msg.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    args = params.get("arguments") if isinstance(params, dict) else None
    if not (isinstance(name, str) and NAME.fullmatch(name)) or not (args is None or isinstance(args, dict)):
        reply = rpc_error(msg_id, -32602, "[guard:invalid-params] bad tool name or arguments")
        return None, reply, deny_event(ctx, "invalid-params")
    assert isinstance(params, dict)
    tool = f"mcp__{ctx.server}__{name}"
    rest = {k: v for k, v in params.items() if k != "name"}
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
        paths = [s for s in strings(rest) if "/" in s or s[:1] in (".", "~")]
        paths += [v for k in PATH_KEYS if isinstance(v := (args or {}).get(k), str)]
        for p in paths:
            if d.verdict == "allow":
                d = check_path(p.removeprefix("file://"), ctx.root, ctx.root, policy)
        blocked = sorted(
            {
                s.kind
                for t in strings(rest)
                for s in detect(t)
                if policy.action(s.kind) == "block"
            }
        )
        if d.verdict == "allow" and blocked:
            rule, reason = "pii-args", f"arguments contain {', '.join(blocked)}"
        elif d.verdict == "allow":
            ctx.pending[key] = "call"
            return msg, None, event | {"verdict": "allow", "rule": "ok"}
        else:
            rule, reason = d.rule, d.reason
    return (
        None,
        rpc_result(msg_id, f"[guard:{rule}] blocked: {reason}"),
        event | {"verdict": "deny", "rule": rule},
    )


def screen(value, ctx: Ctx, policy: Policy) -> tuple[object, str | None, dict]:
    """Every string in value: injection signatures, PII. -> (masked value, withheld reason, audit fields)."""
    done, pii, sigs, why = {}, Counter(), [], None
    for text in dict.fromkeys(strings(value)):
        hits = scan(text, ctx.feed()) if policy.screen_tool_output != "off" else []
        sigs += [h.id for h in hits]
        if policy.screen_tool_output == "block" and worst(hits) == "high":
            why = why or f"[guard:injection] content withheld: attack signature {', '.join(h.id for h in hits)}"
            continue
        if blocked := sorted({sp.kind for sp in detect(text) if policy.action(sp.kind) == "block"}):
            why = why or f"[guard:pii-block] content withheld: contains {', '.join(blocked)}"
            pii.update(blocked)
            continue
        done[text] = text
    fields = ({"pii": dict(pii)} if pii else {}) | ({"signatures": sigs} if sigs else {})
    return (None if why else map_strings(value, lambda t: done[t])), why, fields  # fmt: skip


def on_response(msg, ctx: Ctx) -> tuple[dict | None, dict | None, dict | None]:
    """-> (forward to client, reply to server, audit event). Never raises."""
    try:
        return _response(msg, ctx)
    except Exception:  # fail closed: drop whatever could not be screened
        return None, None, deny_event(ctx, "malformed", channel="tool_output")


def _response(msg, ctx: Ctx):
    event: dict = {"event": "mcp", "agent": ctx.agent, "channel": "tool_output"}
    if not isinstance(msg, dict):
        return None, None, deny_event(ctx, "malformed", channel="tool_output")
    policy = ctx.policy()
    msg_id = msg.get("id")
    if "method" in msg:  # server-initiated: never touches pending
        method = msg["method"]
        if "id" in msg:  # ponytail: sampling/elicitation/roots denied, the agent cannot answer through the guard
            reply = rpc_error(msg_id if usable(msg_id) else None, -32601, "[guard:server-request] not permitted")
            return None, reply, deny_event(ctx, "server-request", method=str(method)[:80])
        if policy is None or not (isinstance(method, str) and method.startswith("notifications/")):
            return None, None, deny_event(ctx, "server-notification", channel="tool_output")
        params, why, fields = screen(msg.get("params"), ctx, policy)
        if why:
            return None, None, event | {"verdict": "deny", "rule": "withheld"} | fields
        out = {"jsonrpc": "2.0", "method": method} | ({"params": params} if "params" in msg else {})
        return out, None, event | {"verdict": "allow", "rule": "ok"} | fields
    kind = ctx.pending.pop(json.dumps(msg_id), None) if usable(msg_id) else None
    if kind is None or not ("result" in msg or "error" in msg):
        return None, None, deny_event(ctx, "unmatched-response", channel="tool_output")
    payload = {k: msg[k] for k in ("result", "error") if k in msg}
    if kind == "list" and "result" in payload:
        result = payload["result"]
        tools = result.get("tools") if isinstance(result, dict) else None
        agent = policy.agents.get(ctx.agent) if policy else None
        payload["result"] = {**(result if isinstance(result, dict) else {}), "tools": [
            t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)
            and NAME.fullmatch(t["name"]) and policy and agent
            and decide_tool(f"mcp__{ctx.server}__{t['name']}", {}, ctx.root, ctx.root, policy, agent).verdict == "allow"
        ] if isinstance(tools, list) else []}  # fmt: skip
    event["id"] = msg_id
    if policy is None:
        cleaned, why, fields = None, "[guard:policy-invalid] content withheld: guard policy invalid", {}
    else:
        cleaned, why, fields = screen(payload, ctx, policy)
    if why is None:
        assert isinstance(cleaned, dict)
        out = {"jsonrpc": "2.0", "id": msg_id} | cleaned
        return out, None, event | {"verdict": "allow", "rule": "ok"} | fields
    if "error" in payload:
        out = rpc_error(msg_id, -32000, why)
    elif kind == "list":
        out = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": []}}
    else:
        out = rpc_result(msg_id, why)
    return out, None, event | {"verdict": "deny", "rule": "withheld"} | fields


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

    ctx = Ctx(a.server, os.environ.get("GUARD_AGENT", "default"), root, policy, feed)
    child = subprocess.Popen(
        cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1
    )
    out_lock, in_lock = threading.Lock(), threading.Lock()

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

    def send(obj: dict) -> None:
        with in_lock:
            try:
                assert child.stdin
                child.stdin.write(json.dumps(obj) + "\n")
                child.stdin.flush()
            except OSError:
                pass  # server gone; the main loop ends on EOF

    def pump_server() -> None:
        assert child.stdout
        for line in child.stdout:
            started = time.perf_counter()
            try:
                msg = json.loads(line)
            except (ValueError, RecursionError):
                continue  # servers must not print non-JSON on stdout; drop it
            out, reply, event = on_response(msg, ctx)
            if out is not None:
                emit(out)
            if reply is not None:
                send(reply)
            log(event, started)

    pump = threading.Thread(target=pump_server, daemon=True)
    pump.start()
    assert child.stdin
    for line in sys.stdin:
        started = time.perf_counter()
        try:
            msg = json.loads(line)
        except (ValueError, RecursionError):
            continue
        forward, reply, event = on_request(msg, ctx)
        if forward is not None:
            send(forward)
        if reply is not None:
            emit(reply)
        log(event, started)
    child.stdin.close()
    code = child.wait()
    pump.join(timeout=5)  # flush the server's last responses before exiting
    return code


if __name__ == "__main__":
    sys.exit(main())
