"""Test tags (markers) and gating. Registered here: root pyproject.toml belongs to other teams.

Default `uv run pytest`: fast unit/contract tests only; integration tests are skipped.
Integration runs real processes, files, sops, Docker, the DGX model, Claude Code:

  uv run pytest -m integration -s                    # all integration, narrated
  uv run pytest -m "integration and pii" -s          # one feature
  uv run pytest -m "integration and negative" -s     # only attacks / blocked cases
  uv run pytest -m "integration and not live" -s     # without the DGX model
  uv run pytest -m agent -s                          # real Claude Code (spends tokens)
"""

import os

import pytest

MARKERS = {
    # kind of run
    "integration": "real processes / files / services; opt-in via -m or RUN_INTEGRATION=1",
    "live": "needs the local LLM on DGX (vLLM over tailnet)",
    "live_api": "calls a commercial API (key from sops .env)",
    "docker": "needs Docker (agent sandbox container)",
    "agent": "runs real Claude Code headless; spends tokens; only with -m agent",
    # outcome
    "positive": "allowed / passes through the control",
    "negative": "attack or violation that must be blocked / redacted",
    # control area
    "pii": "personal data detection, anonymization, pseudonymization",
    "consent": "authentication + consent before anonymization",
    "vault": "sops/age sealed vault",
    "hook": "Claude Code hook (PreToolUse / UserPromptSubmit)",
    "mcp": "MCP proxy",
    "sandbox": "container isolation (kernel boundary)",
    "injection": "prompt injection / exploit signatures",
    "policy": "central policy, live reload, fail-closed",
    "audit": "audit log and report",
    "harness": "harness adapters (Cursor, Gemini, Codex, Claude Agent SDK, OpenAI Agents, LangChain)",
}


def pytest_configure(config):
    for name, help_ in MARKERS.items():
        config.addinivalue_line("markers", f"{name}: {help_}")


def pytest_collection_modifyitems(config, items):
    expr = config.option.markexpr or ""
    run_integration = os.environ.get("RUN_INTEGRATION") == "1" or "integration" in expr or "agent" in expr
    for item in items:
        if "integration" in item.keywords and not run_integration:
            item.add_marker(pytest.mark.skip(reason="integration: run with -m integration"))
        elif "agent" in item.keywords and "agent" not in expr:
            item.add_marker(pytest.mark.skip(reason="spends tokens: run with -m agent"))
