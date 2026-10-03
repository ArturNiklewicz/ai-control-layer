"""In-process adapters for agent SDKs. SDK imports are lazy: none of them is a dependency.

Claude Agent SDK:   ClaudeAgentOptions(hooks=claude_agent_hooks(agent="default"))
OpenAI Agents SDK:  Agent(input_guardrails=[g_in], ...) from openai_agents_guardrails()
                    @tool(tool_input_guardrails=[t_in], tool_output_guardrails=[t_out])
LangChain 1.x:      create_agent(..., middleware=[langchain_middleware()])
"""

import asyncio
import json
from typing import cast

from src.guard.adapters import Verdict, check

# --- decision helpers in harness-neutral terms (also usable from any custom loop) ---


def check_prompt(text: str, harness: str, agent: str | None = None) -> Verdict:
    return check(
        {"hook_event_name": "UserPromptSubmit", "prompt": text}, harness, agent=agent
    )


def check_tool_call(
    tool: str, args: object, harness: str, agent: str | None = None
) -> Verdict:
    if isinstance(args, str):  # SDKs pass JSON-encoded arguments
        try:
            args = json.loads(args or "{}")
        except ValueError:
            args = None
    return check(
        {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": args},
        harness,
        agent=agent,
    )


def check_tool_output(
    tool: str, output: object, harness: str, agent: str | None = None
) -> Verdict:
    return check(
        {"hook_event_name": "PostToolUse", "tool_name": tool, "tool_response": output},
        harness,
        agent=agent,
    )


# --- Claude Agent SDK: hooks, not can_use_tool (that one only fires on "ask" outcomes) ---


def claude_agent_hook(agent: str | None = None):
    async def hook(input_data: dict, tool_use_id: str | None, context: object) -> dict:
        v = await asyncio.to_thread(
            check, dict(input_data), "claude-agent-sdk", None, agent
        )
        if v.verdict == "allow":
            return {}
        if input_data.get("hook_event_name") == "PreToolUse":
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": v.verdict,
                    "permissionDecisionReason": v.reason}}  # fmt: skip
        return {"decision": "block", "reason": v.reason}

    return hook


def claude_agent_hooks(agent: str | None = None) -> dict:
    from claude_agent_sdk import HookMatcher  # pyright: ignore[reportMissingImports]
    from claude_agent_sdk.types import HookCallback  # pyright: ignore[reportMissingImports]

    h = cast("HookCallback", claude_agent_hook(agent))  # TypedDict inputs are plain dicts at runtime
    return {
        ev: [HookMatcher(hooks=[h], timeout=15)]
        for ev in ("PreToolUse", "PostToolUse", "UserPromptSubmit")
    }


# --- OpenAI Agents SDK guardrails ---


def openai_agents_guardrails(agent: str | None = None):
    """-> (input_guardrail, tool_input_guardrail, tool_output_guardrail).
    ponytail: tool guardrails cover function tools and local MCP servers only (SDK limit);
    hosted tools need the gateway (base_url) for request/response screening."""
    from agents import (  # pyright: ignore[reportMissingImports]
        GuardrailFunctionOutput,
        ToolGuardrailFunctionOutput,
        input_guardrail,
    )
    from agents import tool_input_guardrail, tool_output_guardrail  # pyright: ignore[reportMissingImports]

    @input_guardrail(
        run_in_parallel=False
    )  # block before the agent spends tokens or calls tools
    async def guard_input(ctx, agent_, input):
        text = input if isinstance(input, str) else json.dumps(input, default=str)
        v = await asyncio.to_thread(check_prompt, text, "openai-agents", agent)
        return GuardrailFunctionOutput(
            output_info={"rule": v.rule, "reason": v.reason},
            tripwire_triggered=v.blocked,
        )

    @tool_input_guardrail
    def guard_tool_input(data):
        c = data.context
        v = check_tool_call(
            str(getattr(c, "tool_name", "")),
            getattr(c, "tool_arguments", "{}"),
            "openai-agents",
            agent,
        )
        return (
            ToolGuardrailFunctionOutput.allow()
            if v.verdict == "allow"
            else ToolGuardrailFunctionOutput.reject_content(v.reason)
        )

    @tool_output_guardrail
    def guard_tool_output(data):
        v = check_tool_output(
            str(getattr(data.context, "tool_name", "")),
            data.output,
            "openai-agents",
            agent,
        )
        return (
            ToolGuardrailFunctionOutput.allow()
            if v.verdict == "allow"
            else ToolGuardrailFunctionOutput.reject_content(v.reason)
        )

    return guard_input, guard_tool_input, guard_tool_output


# --- LangChain 1.x middleware ---


def langchain_tool_guard(request, handler, agent: str | None = None):
    """wrap_tool_call body: block before the tool runs, screen what it returns."""
    from langchain.messages import ToolMessage  # pyright: ignore[reportMissingImports]

    tc = request.tool_call
    v = check_tool_call(tc["name"], tc.get("args"), "langchain", agent)
    if v.verdict != "allow":  # no human in the loop here: ask is a deny
        return ToolMessage(content=v.reason, tool_call_id=tc["id"], status="error")
    out = handler(request)
    if (
        w := check_tool_output(
            tc["name"], getattr(out, "content", out), "langchain", agent
        )
    ).blocked:
        return ToolMessage(content=w.reason, tool_call_id=tc["id"], status="error")
    return out


def langchain_middleware(agent: str | None = None):
    from langchain.agents.middleware import wrap_tool_call  # pyright: ignore[reportMissingImports]

    @wrap_tool_call
    def guard(request, handler):
        return langchain_tool_guard(request, handler, agent)

    return guard
