"""Central policy: one TOML file, parsed into frozen data. Parsing is pure; `load` is the shell.

Hook and CLI re-read the file on every call, so edits apply immediately (no restart).
An invalid file is an Err; callers fail closed.
"""

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from src.result import Err, Ok, Result, attempt

type Action = Literal["off", "anonymize", "pseudonymize", "block"]
# monitor: log would-be denials, allow everything
type Mode = Literal["enforce", "monitor"]
type Screen = Literal["off", "warn", "block"]  # what a signature hit does on a channel
ACTIONS = get_args(Action.__value__)


@dataclass(frozen=True, slots=True)
class Agent:
    """What one agent identity may do. Identity comes from the harness, never from the model."""

    commands: tuple[tuple[str, ...], ...]  # allowed command prefixes, tokenized
    ask: tuple[tuple[str, ...], ...]  # irreversible: a human confirms
    tools_deny: frozenset[str]
    mcp_allow: tuple[str, ...]  # fnmatch patterns over mcp__server__tool


@dataclass(frozen=True, slots=True)
class Model:
    upstream: str  # OpenAI-compatible base_url
    key_env: str  # env var holding the upstream key ("" = none)
    input_usd_mtok: float
    output_usd_mtok: float


@dataclass(frozen=True, slots=True)
class Principal:
    """A gateway caller. Identity = API key (stored hashed), never a field in the request."""

    key_sha256: str
    models: tuple[str, ...]
    daily_usd: float
    daily_tokens: int


@dataclass(frozen=True, slots=True)
class Gateway:
    models: Mapping[str, Model]  # the allowed-models list: anything else is refused
    principals: Mapping[str, Principal]
    injection: Screen
    pii_public: Literal["block", "pseudonymize"]  # PII bound for a non-private upstream


@dataclass(frozen=True, slots=True)
class Policy:
    mode: Mode
    pii_default: Action
    pii_kinds: Mapping[str, Action]
    semantic: bool
    semantic_fail_closed: bool
    scan_reads: bool
    deny_paths: tuple[str, ...]
    deny_tokens: frozenset[str]
    agents: Mapping[str, Agent]
    vault_path: str
    age_recipient: str
    llm_base_url: str
    llm_model: str
    feed_path: str
    screen_prompt: Screen
    screen_reads: Screen
    screen_tool_output: Screen
    consent_hours: float
    gateway: Gateway
    judge_threshold: float  # 0 = judge off; else score >= threshold counts as an attack
    judge_fail_closed: bool

    def action(self, kind: str) -> Action:
        return self.pii_kinds.get(kind, self.pii_default)


@dataclass(frozen=True, slots=True)
class PolicyError:
    detail: str


def prefixes(items: list[str]) -> tuple[tuple[str, ...], ...]:
    return tuple(tuple(i.split()) for i in items)


def parse(raw: dict) -> Result[Policy, PolicyError]:
    try:
        pii, cmd, inj = raw.get("pii", {}), raw["commands"], raw.get("injection", {})
        screens = {
            k: inj.get(k, "warn") for k in ("user_prompt", "reads", "tool_output")
        }
        if bad := {
            k: v for k, v in screens.items() if v not in ("off", "warn", "block")
        }:
            return Err(
                PolicyError(f"injection actions must be off|warn|block, got {bad}")
            )
        actions = {
            "default": pii.get("default", "pseudonymize"),
            **pii.get("kinds", {}),
        }
        if bad := {k: v for k, v in actions.items() if v not in ACTIONS}:
            return Err(PolicyError(f"unknown pii action {bad}; use one of {ACTIONS}"))
        if (mode := raw.get("mode", "enforce")) not in ("enforce", "monitor"):
            return Err(PolicyError(f"mode must be enforce|monitor, got {mode!r}"))
        base = {
            "commands": cmd["allow"],
            "ask": cmd.get("ask", []),
            "tools_deny": raw.get("tools", {}).get("deny", []),
            "mcp_allow": raw.get("mcp", {}).get("allow", []),
        }
        agents = {
            name: Agent(
                prefixes(o.get("commands", base["commands"])),
                prefixes(o.get("ask", base["ask"])),
                frozenset(o.get("tools_deny", base["tools_deny"])),
                tuple(o.get("mcp_allow", base["mcp_allow"])),
            )
            for name, o in {"default": {}, **raw.get("agents", {})}.items()
        }
        gw = raw.get("gateway", {})
        if gw.get("injection", "block") not in ("off", "warn", "block"):
            return Err(PolicyError("gateway.injection must be off|warn|block"))
        if gw.get("pii_public", "block") not in ("block", "pseudonymize"):
            return Err(PolicyError("gateway.pii_public must be block|pseudonymize"))
        models = {
            name: Model(
                m["upstream"].rstrip("/"),
                m.get("key_env", ""),
                float(m.get("input_usd_mtok", 0)),
                float(m.get("output_usd_mtok", 0)),
            )
            for name, m in gw.get("models", {}).items()
        }
        principals = {
            name: Principal(
                p["key_sha256"].lower(),
                tuple(p.get("models", models)),
                float(p.get("daily_usd", 0)),
                int(p.get("daily_tokens", 0)),
            )
            for name, p in gw.get("principals", {}).items()
        }
        if bad := {m for p in principals.values() for m in p.models} - set(models):
            return Err(PolicyError(f"gateway principals reference unknown models {bad}"))
        judge = raw.get("judge", {})
        threshold = float(judge.get("threshold", 0)) if judge.get("enabled", False) else 0.0
        if not 0 <= threshold <= 1:
            return Err(PolicyError("judge.threshold must be in [0, 1]"))
        return Ok(
            Policy(
                mode=mode,
                pii_default=actions.pop("default"),
                pii_kinds=actions,
                semantic=bool(pii.get("semantic", False)),
                semantic_fail_closed=pii.get("semantic_on_error", "fail_closed")
                == "fail_closed",
                scan_reads=bool(pii.get("scan_reads", True)),
                deny_paths=tuple(raw.get("paths", {}).get("deny", [])),
                deny_tokens=frozenset(cmd.get("deny_tokens", [])),
                agents=agents,
                vault_path=raw.get("vault", {}).get("path", ".guard/vault.sops.json"),
                age_recipient=raw.get("vault", {}).get("age_recipient", ""),
                llm_base_url=raw.get("llm", {}).get("base_url", ""),
                llm_model=raw.get("llm", {}).get("model", ""),
                feed_path=inj.get("feed", "src/guard/signatures.json"),
                screen_prompt=inj.get("user_prompt", "warn"),
                screen_reads=inj.get("reads", "warn"),
                screen_tool_output=inj.get("tool_output", "block"),
                consent_hours=float(raw.get("consent", {}).get("ttl_hours", 8)),
                gateway=Gateway(
                    models,
                    principals,
                    gw.get("injection", "block"),
                    gw.get("pii_public", "block"),
                ),
                judge_threshold=threshold,
                judge_fail_closed=judge.get("on_error", "fail_closed") == "fail_closed",
            )
        )
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        return Err(PolicyError(f"malformed policy: {e!r}"))


def load(path: Path) -> Result[Policy, PolicyError]:
    return attempt(
        lambda: tomllib.loads(path.read_text()),
        (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError),
        lambda e: PolicyError(f"{path}: {e}"),
    ).bind(parse)
