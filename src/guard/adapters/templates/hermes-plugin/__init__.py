"""AI Control Layer bridge plugin for Hermes Agent.

Hermes plugin hooks (pre_tool_call, transform_tool_result, pre_llm_call) are forwarded to the
guard decision core — `python -m src.guard.adapters.cli_hooks hermes` in the GUARD venv — over
stdin/stdout JSON. One policy, one decision core, one audit log for every harness; this file
makes no security decision of its own.

Fail closed: a missing GUARD_PYTHON, a crashed or timed-out guard process, or unparseable
stdout all return a block directive (Hermes also fails pre_tool_call closed on its own
callback timeout, but the other two hooks fail open — so the guard must decide, not assume).

Installed by src/guard/sandbox/run.sh at .hermes/plugins/ai-control-layer (project plugin;
the container sets HERMES_ENABLE_PROJECT_PLUGINS=1).
"""

import json
import os
import subprocess

GUARD_PY = os.environ.get("GUARD_PYTHON", "/opt/venv/bin/python")
GUARD_CWD = os.environ.get("GUARD_CWD", "/repo")  # becomes the guard's project root
GUARD_PATH = os.environ.get("GUARD_PYTHONPATH", GUARD_CWD)  # where src.guard is importable from
TIMEOUT_S = float(os.environ.get("GUARD_HOOK_TIMEOUT_S", "25"))  # < plugins.hook_callback_timeout
_FALLBACK_BLOCK = {"action": "block", "message": "[guard:internal-error] guard process unavailable"}


def _ask_guard(event: str, payload: dict, on_fail: dict) -> dict:
    payload = {"hook_event_name": event, **payload}
    try:
        p = subprocess.run(
            [GUARD_PY, "-m", "src.guard.adapters.cli_hooks", "hermes"],
            input=json.dumps(payload, ensure_ascii=False, default=str),
            capture_output=True, text=True, timeout=TIMEOUT_S, cwd=GUARD_CWD,
            env={**os.environ, "PYTHONPATH": GUARD_PATH},
        )  # fmt: skip
        out = json.loads(p.stdout)
        return out if isinstance(out, dict) else on_fail
    except Exception as exc:  # noqa: BLE001 — a guard that cannot answer denies, never allows
        msg = f"[guard:internal-error] {type(exc).__name__}"
        return {"result": f"{msg}: tool output withheld"} if "result" in on_fail else {"action": "block", "message": msg}


def on_pre_tool_call(tool_name=None, args=None, **_):
    out = _ask_guard("pre_tool_call", {"tool_name": tool_name, "tool_input": args}, _FALLBACK_BLOCK)
    if out.get("action") in ("block", "approve"):
        return out
    return None  # {} / unknown keys: no objection


def on_transform_tool_result(tool_name=None, args=None, result=None, **_):
    # fail closed too: a broken guard replaces the result with a withholding notice, so the
    # model never sees an unscreened tool output (Hermes itself fails this hook open).
    out = _ask_guard(
        "transform_tool_result", {"tool_name": tool_name, "tool_input": args, "result": result},
        {"result": "[guard:internal-error] tool output withheld: the guard could not screen it"},
    )
    r = out.get("result")
    return r if isinstance(r, str) else None  # first string return replaces the tool result


def on_pre_llm_call(user_message=None, **_):
    out = _ask_guard("pre_llm_call", {"user_message": user_message}, {})
    c = out.get("context")
    return c if isinstance(c, str) else None  # Hermes cannot block a prompt here; the gateway is the gate


def register(ctx):
    ctx.register_hook("pre_tool_call", on_pre_tool_call)
    ctx.register_hook("transform_tool_result", on_transform_tool_result)
    ctx.register_hook("pre_llm_call", on_pre_llm_call)