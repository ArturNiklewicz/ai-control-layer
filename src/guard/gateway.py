"""OpenAI-compatible LLM gateway: swap `base_url` in any SDK and every call is governed.

  uv run python -m src.guard.gateway [--listen 127.0.0.1:8787]
  OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="<principal key>")

Per request: API key -> principal; model must be on the allowed list; daily token / USD budget
(spend seeded from the audit log, so a restart does not reset it); injection signatures on
user/tool messages; PII bound for a non-private upstream is refused or pseudonymized (and
restored in the reply); `block` PII kinds are masked in the reply. Policy re-read per request.
Any guard failure answers an error before the upstream is called (fail closed).
"""

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from typing import Any
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from src.guard import anthropic, audit
from src.guard.anonymizer import Anonymizer, json_escape
from src.guard.judge import Verdict, judge
from src.guard.injection import Signature, load_feed, scan, worst
from src.guard.pii import Span, anonymize, detect, pseudonymize, restore
from src.guard.fsio import atomic_write
from src.guard.policy import Gateway, Model, Policy, Principal, load
from src.result import Err, Ok, Result

# sha256("demo-key-change-me"): allowed on loopback only
DEMO_KEY_SHA256 = "090d1548c9d65f413a1a2c828a0bee3a7ae02d2137caf51e6029e6c3cb1f1fa4"
SCREENED_ROLES = (
    "user",
    "tool",
    "function",
)  # system/assistant come from the app itself


@dataclass(frozen=True, slots=True)
class Refusal:
    status: int
    rule: str
    reason: str


# --- pure core ---


def principal_of(gw: Gateway, auth: str) -> tuple[str, Principal] | None:
    key = auth.removeprefix("Bearer ").strip()
    digest = hashlib.sha256(key.encode()).hexdigest()
    return next(
        ((n, p) for n, p in gw.principals.items() if key and p.key_sha256 == digest),
        None,
    )


def cost(model: Model, tokens_in: int, tokens_out: int) -> float:
    return (tokens_in * model.input_usd_mtok + tokens_out * model.output_usd_mtok) / 1e6


def admit(gw: Gateway, who: Principal, model: str, spent: dict) -> Refusal | None:
    if model not in gw.models or model not in who.models:
        return Refusal(
            403, "model-denied", f"model {model!r} is not allowed for this principal"
        )
    if who.daily_tokens and spent["tokens"] >= who.daily_tokens:
        return Refusal(
            429, "budget-tokens", f"daily token budget {who.daily_tokens} spent"
        )
    if who.daily_usd and spent["usd"] >= who.daily_usd:
        return Refusal(429, "budget-usd", f"daily budget ${who.daily_usd:.2f} spent")
    return None


# identifiers the upstream must get back verbatim (a call id can look like a phone number)
VERBATIM = frozenset({"model", "role", "type", "id", "tool_call_id"})


def strings(value, keys: bool = True) -> list[str]:
    """Every string a model would read: values and keys, any depth, any content-part type.
    ponytail: image/audio parts pass unscreened; add OCR/ASR screening if needed."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() if k not in VERBATIM for s in [k] * keys + strings(v, keys)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v, keys)]
    return []


def map_strings(value, f: Callable[[str], str]) -> Any:
    """f over the strings of `strings`; a key f would change is refused by f's caller."""
    if isinstance(value, str):
        return f(value)
    if isinstance(value, dict):
        return {k if k in VERBATIM else f(k): v if k in VERBATIM else map_strings(v, f) for k, v in value.items()}
    if isinstance(value, list):
        return [map_strings(v, f) for v in value]
    return value


def new_turn(messages: list) -> list:
    """Messages after the last assistant turn: earlier ones were judged on their own request."""
    last = max((i for i, m in enumerate(messages) if m.get("role") == "assistant"), default=-1)
    return messages[last + 1 :]


def screen_injection(
    messages: list,
    policy: Policy,
    feed: tuple[Signature, ...],
    judge_fn: Callable[[str], Result[Verdict, object]] | None = None,
) -> tuple[Refusal | None, dict]:
    """Signatures over every user/tool message; the judge only on this turn's new text and
    only when no high signature already decided (latency: one local-model call per turn)."""
    how = policy.gateway.injection
    if how == "off":
        return None, {}
    untrusted = [t for m in messages if m.get("role") in SCREENED_ROLES for t in strings(m)]
    hits = [h for t in untrusted for h in scan(t, feed)]
    info: dict = {"signatures": sorted({h.id for h in hits})} if hits else {}
    if worst(hits) == "high":
        reason = f"attack signature {', '.join(info['signatures'])} in request"
        return (Refusal(400, "injection", reason) if how == "block" else None), info
    fresh = "\n\n".join(t for m in new_turn(messages) if m.get("role") in SCREENED_ROLES for t in strings(m, keys=False))
    if not (judge_fn and policy.judge_threshold and fresh.strip()):
        return None, info
    match judge_fn(fresh):
        case Err(e):
            info["judge"] = "error"
            if policy.judge_fail_closed:
                return Refusal(503, "judge-unavailable", str(e)), info
            return None, info
        case Ok(v):
            info |= {"judge_score": round(v.score, 2), "judge_category": v.category}
            if v.score >= policy.judge_threshold and how == "block":
                return Refusal(400, "injection-judge", f"{v.category}: {v.reason}"), info
    return None, info


def screen_pii(
    body: dict,
    policy: Policy,
    public: bool,
    spans_of: Callable[[str], Result[list[Span], str]],
) -> Result[tuple[dict, dict[str, str], dict[str, int]], Refusal]:
    """Private upstream: data stays on our network, pass. Public: every string of the body
    (messages, tools, tool_calls, user, schemas) is screened; `block` kinds or
    pii_public=block refuse, otherwise pseudonymize with a request-scoped vault."""
    if not public:
        return Ok((body, {}, {}))
    found: dict[str, int] = defaultdict(int)
    vault: dict[str, str] = {}

    def mask(t: str) -> str:
        nonlocal vault
        match spans_of(t):
            case Err(e):
                raise _Refuse(Refusal(503, "pii-detector", e))
            case Ok(spans):
                spans = [s for s in spans if policy.action(s.kind) != "off"]
        for s in spans:
            found[s.kind] += 1
        if blocked := sorted({s.kind for s in spans if policy.action(s.kind) == "block"}):
            raise _Refuse(Refusal(400, "pii-block", f"request contains {', '.join(blocked)}"))
        if spans and policy.gateway.pii_public == "block":
            raise _Refuse(Refusal(400, "pii-public", f"personal data ({', '.join(sorted(found))}) bound for a public model"))
        masked, vault = pseudonymize(t, spans, vault)
        return masked

    try:
        out: dict = map_strings(body, mask)
        return Ok((out, vault, dict(found)))
    except _Refuse as r:
        return Err(r.refusal)


class _Refuse(Exception):
    def __init__(self, refusal: Refusal):
        self.refusal = refusal


def screen_reply(
    text: str, policy: Policy, vault: dict[str, str]
) -> tuple[str, dict[str, int]]:
    """Restore our pseudonyms; mask `block` kinds (secrets, cards) the model emits."""
    text = restore(text, vault)
    spans = [s for s in detect(text) if policy.action(s.kind) == "block"]
    counts: dict[str, int] = defaultdict(int)
    for s in spans:
        counts[s.kind] += 1
    return anonymize(text, spans), dict(counts)


# --- shell ---

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
POLICY = Path(os.environ.get("GUARD_POLICY") or ROOT / "src/guard/policy.toml")


class Ledger:
    """Today's spend per principal, persisted to a host-only file (never the audit log: the
    sandbox can append to that, so a truncated log would reset every budget).
    ponytail: a request is admitted on spend *before* it, so the last call can overrun the
    budget by one response; reserve max_tokens up front if that matters."""

    def __init__(self, path: Path):
        self.path, self.lock = path, threading.Lock()
        try:
            saved = json.loads(path.read_text())
        except (OSError, ValueError):
            saved = {}
        self.day = saved.get("day", "")
        self.spent = defaultdict(lambda: {"tokens": 0, "usd": 0.0}, saved.get("spent", {}))

    def roll(self) -> None:
        if (today := datetime.now(UTC).date().isoformat()) != self.day:
            self.day, self.spent = today, defaultdict(lambda: {"tokens": 0, "usd": 0.0})

    def get(self, name: str) -> dict:
        with self.lock:
            self.roll()
            return dict(self.spent[name])

    def add(self, name: str, tokens: int, usd: float) -> None:
        with self.lock:
            self.roll()
            self.spent[name]["tokens"] += max(0, tokens)
            self.spent[name]["usd"] += max(0.0, usd)
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_write(self.path, json.dumps({"day": self.day, "spent": self.spent}))


def ledger_path() -> Path:
    from src.guard.cli import state

    return state() / "gateway-spend.json"


LEDGER = Ledger(ledger_path())


@lru_cache(maxsize=64)
def public(url: str) -> bool:
    from src.guard.cli import is_local

    return not is_local(url)


def judge_of(policy: Policy) -> Callable[[str], Result[Verdict, object]] | None:
    if not policy.judge_threshold:
        return None
    if public(policy.llm_base_url):  # requests may carry PII: the judge must be ours
        return lambda _: Err(f"llm.base_url {policy.llm_base_url!r} is not private")
    complete = local_completer(policy.llm_base_url, policy.llm_model)
    return lambda t: judge(t, complete)


@lru_cache(maxsize=4)
def local_completer(base_url: str, model: str):
    from openai import OpenAI

    from src.guard.cli import NO_THINKING
    from src.llm import completer

    c = completer(OpenAI(base_url=base_url, api_key=os.environ.get("GUARD_LLM_KEY", "local"), timeout=30, max_retries=0), model)
    return lambda m, **kw: c(m, extra_body=NO_THINKING, **kw).map(lambda r: r.text)


def spans_of(policy: Policy) -> Callable[[str], Result[list[Span], str]]:
    if not policy.semantic:
        return lambda t: Ok(detect(t))
    from src.guard.cli import (
        find_spans,
    )  # NER on the local model, fail-closed per policy

    return lambda t: find_spans(t, policy)


ENGINES: dict[tuple, Anonymizer] = {}
ENGINE_LOCK = threading.Lock()


def engine(policy: Policy) -> Anonymizer:
    """One anonymizer (vault + caches) per model config, state in the host-only dir."""
    key = (policy.semantic, policy.semantic_fail_closed, policy.llm_base_url, policy.llm_model)
    with ENGINE_LOCK:
        if key not in ENGINES:
            from src.guard.cli import state

            if not policy.semantic:
                complete = None
            elif public(policy.llm_base_url):  # PII must never reach a public model
                bad = f"llm.base_url {policy.llm_base_url!r} is not private"
                complete = lambda *a, **kw: Err(bad)  # noqa: E731
            else:
                complete = local_completer(policy.llm_base_url, policy.llm_model)
            ENGINES[key] = Anonymizer(state() / "anonymizer.json", complete, policy.semantic_fail_closed)
        return ENGINES[key]


HOP = frozenset({"host", "content-length", "connection", "accept-encoding", "transfer-encoding", "keep-alive"})


def upstream_request(model: Model, body: dict) -> urllib.request.Request:
    headers = {"Content-Type": "application/json"}
    if model.key_env and (key := os.environ.get(model.key_env)):
        headers["Authorization"] = f"Bearer {key}"
    return urllib.request.Request(
        model.upstream + "/chat/completions",
        json.dumps(body).encode(),
        headers,
        method="POST",
    )


def usage_of(obj: dict) -> tuple[int, int]:
    u = obj.get("usage") or {}
    return int(u.get("prompt_tokens") or 0), int(u.get("completion_tokens") or 0)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # the audit log is the log
        pass

    def send_json(self, status: int, obj: dict) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def refuse(self, r: Refusal, event: dict) -> None:
        audit.record(
            ROOT, event | {"verdict": "deny", "rule": r.rule}, datetime.now(UTC)
        )
        self.send_json(
            r.status,
            {
                "error": {
                    "message": f"[guard:{r.rule}] {r.reason}",
                    "type": "guard",
                    "code": r.rule,
                }
            },
        )

    def caller(self) -> tuple[Policy, str, Principal] | Refusal:
        match load(POLICY):
            case Err(e):
                return Refusal(503, "policy-invalid", e.detail)
            case Ok(policy):
                pass
        if not (
            who := principal_of(policy.gateway, self.headers.get("Authorization", ""))
        ):
            return Refusal(401, "unknown-principal", "invalid API key")
        return policy, *who

    def do_HEAD(self):  # Claude Code's connection-warming probe
        self.send_response(200 if self.path.startswith("/api/hello") else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        match self.caller():
            case Refusal() as r:
                return self.refuse(r, {"event": "gateway", "path": self.path})
            case policy, name, who:
                pass
        if self.path.rstrip("/") == "/v1/models":
            return self.send_json(
                200,
                {
                    "object": "list",
                    "data": [
                        {"id": m, "object": "model", "owned_by": "guard"}
                        for m in who.models
                    ],
                },
            )
        if self.path.rstrip("/") == "/v1/budget":
            return self.send_json(
                200,
                {
                    "principal": name,
                    "spent": LEDGER.get(name),
                    "daily_tokens": who.daily_tokens,
                    "daily_usd": who.daily_usd,
                },
            )
        self.send_json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        t0 = time.perf_counter()
        event: dict = {"event": "gateway"}
        try:
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}"
            )
            path = self.path.split("?")[0].rstrip("/")
            if path in ("/v1/messages", "/v1/messages/count_tokens") and isinstance(body, dict):
                return self.messages(path, body, event, t0)
            if (
                self.path.rstrip("/") != "/v1/chat/completions"
                or not isinstance(body, dict)
                or not isinstance(body.get("messages"), list)
            ):
                return self.refuse(
                    Refusal(
                        400, "bad-request", "POST /v1/chat/completions with messages[]"
                    ),
                    event,
                )
            match self.caller():
                case Refusal() as r:
                    return self.refuse(r, event)
                case policy, name, who:
                    pass
            model_name = str(body.get("model", ""))
            event |= {"principal": name, "model": model_name}
            if r := admit(policy.gateway, who, model_name, LEDGER.get(name)):
                return self.refuse(r, event)
            model = policy.gateway.models[model_name]
            match load_feed(ROOT / policy.feed_path):
                case Err(e):
                    return self.refuse(Refusal(503, "feed-invalid", e.detail), event)
                case Ok(feed):
                    pass
            messages = [m for m in body["messages"] if isinstance(m, dict)]
            r, info = screen_injection(messages, policy, feed, judge_of(policy))
            event |= info
            if r:
                return self.refuse(r, event)
            is_public = public(model.upstream)
            match screen_pii(body | {"messages": messages}, policy, is_public, spans_of(policy)):
                case Err(r):
                    return self.refuse(r, event)
                case Ok((body, vault, pii)):
                    event |= {"pii": pii} if pii else {}
            event |= {
                "upstream": "public" if is_public else "private",
                "guard_ms": round((time.perf_counter() - t0) * 1000, 2),
            }
            if body.get("stream"):
                opts = body.get("stream_options")
                body["stream_options"] = (opts if isinstance(opts, dict) else {}) | {"include_usage": True}
                return self.stream(model, body, policy, name, event, t0)
            return self.complete(model, body, policy, vault, name, event, t0)
        except (
            Exception
        ) as e:  # fail closed: nothing reaches the upstream after a guard bug
            self.refuse(Refusal(500, "internal-error", type(e).__name__), event)

    # --- Anthropic Messages API (Claude Code: ANTHROPIC_BASE_URL) ---

    def messages(self, path: str, body: dict, event: dict, t0: float):
        """The caller's own Anthropic credential goes upstream untouched: this proxy does not
        authenticate, it anonymizes. Every string leaves pseudonymized or not at all."""
        match load(POLICY):
            case Err(e):
                return self.refuse(Refusal(503, "policy-invalid", e.detail), event)
            case Ok(policy):
                pass
        gw, model = policy.gateway, str(body.get("model", ""))
        cred = self.headers.get("x-api-key") or self.headers.get("Authorization") or ""
        event |= {"api": "anthropic", "model": model, "principal": "anthropic:" + hashlib.sha256(cred.encode()).hexdigest()[:8]}
        if not any(fnmatch.fnmatchcase(model, p) for p in gw.anthropic_models):
            return self.refuse(Refusal(403, "model-denied", f"model {model!r} is not allowed"), event)
        eng = engine(policy)
        match eng.pseudonymize_many(anthropic.strings(body), policy):
            case Err(e):
                return self.refuse(Refusal(503, "pii-detector", e), event)
            case Ok((sent, counts)):
                pass
        out = anthropic.walk(body, lambda t: sent[t])
        if hits := sorted({h.id for t in sent.values() for h in self.feed_hits(policy, t)}):
            event["signatures"] = hits  # ponytail: audit only; a block would kill the session (history is resent)
        event |= {"pii": dict(counts)} if counts else {}
        event["guard_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP} | {"Accept-Encoding": "identity"}
        req = urllib.request.Request(gw.anthropic_upstream + self.path, json.dumps(out, ensure_ascii=False).encode(), headers, method="POST")
        try:
            resp = urllib.request.urlopen(req, timeout=600)
        except urllib.error.HTTPError as e:
            audit.record(ROOT, event | {"verdict": "allow", "rule": f"upstream-{e.code}"}, datetime.now(UTC))
            return self.relay(e.code, e.headers, e.read())
        except (urllib.error.URLError, TimeoutError) as e:
            return self.refuse(Refusal(502, "upstream-unreachable", str(e)), event)
        done = lambda usage: (eng.save(), audit.record(ROOT, event | {  # noqa: E731
            "verdict": "allow", "rule": "ok", "tokens_in": usage[0], "tokens_out": usage[1], "tokens": sum(usage),
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1)}, datetime.now(UTC)))  # fmt: skip
        with resp:
            if path.endswith("count_tokens") or not body.get("stream"):
                reply = json.loads(resp.read())
                if not path.endswith("count_tokens"):
                    reply = anthropic.restore_reply(reply, eng.restore, eng.remember)
                u = reply.get("usage") or {}
                done((int(u.get("input_tokens") or reply.get("input_tokens") or 0), int(u.get("output_tokens") or 0)))
                self.relay(resp.status, resp.headers, json.dumps(reply, ensure_ascii=False).encode())
            else:
                self.relay_stream(resp, eng, done)

    def feed_hits(self, policy: Policy, text: str):
        match load_feed(ROOT / policy.feed_path):
            case Ok(feed):
                return scan(text, feed)
        return []

    def relay(self, status: int, headers, data: bytes) -> None:
        self.send_response(status)
        for k, v in headers.items():
            if k.lower() not in HOP | {"content-encoding"}:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def relay_stream(self, resp, eng: Anonymizer, done: Callable[[tuple[int, int]], object]) -> None:
        self.send_response(resp.status)
        for k, v in resp.headers.items():
            if k.lower() not in HOP | {"content-encoding"}:
                self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        sr = anthropic.StreamRestorer(eng.restore, lambda t: eng.restore(t, json_escape), eng.remember)
        name, data = "", []
        for raw in resp:
            line = raw.decode("utf-8").rstrip("\r\n")
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].strip())
            elif line == "" and data:
                try:
                    events = sr.event(name, json.loads("\n".join(data)))
                except ValueError:
                    events = []
                    self.wfile.write(f"event: {name}\ndata: {chr(10).join(data)}\n\n".encode())
                for n, d in events:
                    if n == "message_stop":  # account before the client may hang up
                        done((sr.usage[0], sr.usage[1]))
                    self.wfile.write(anthropic.sse(n, d))
                self.wfile.flush()
                name, data = "", []

    def call(self, model: Model, body: dict, event: dict):
        try:
            return urllib.request.urlopen(upstream_request(model, body), timeout=300)
        except urllib.error.HTTPError as e:
            data = e.read()
            audit.record(
                ROOT,
                event | {"verdict": "allow", "rule": f"upstream-{e.code}"},
                datetime.now(UTC),
            )
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (urllib.error.URLError, TimeoutError) as e:
            self.refuse(Refusal(502, "upstream-unreachable", str(e)), event)
        return None

    def account(
        self,
        model: Model,
        name: str,
        event: dict,
        t0: float,
        usage: tuple[int, int],
        extra: dict,
    ) -> None:
        usd = cost(model, *usage)
        LEDGER.add(name, sum(usage), usd)
        audit.record(
            ROOT,
            event
            | extra
            | {
                "verdict": "allow",
                "rule": "ok",
                "tokens_in": usage[0],
                "tokens_out": usage[1],
                "tokens": sum(usage),
                "cost_usd": round(usd, 6),
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
            },
            datetime.now(UTC),
        )

    def complete(self, model, body, policy, vault, name, event, t0):
        if not (resp := self.call(model, body, event)):
            return
        with resp:
            reply = json.loads(resp.read())
        masked: dict[str, int] = {}
        for choice in reply.get("choices", []):
            msg = choice.get("message") or {}
            if isinstance(msg.get("content"), str):
                msg["content"], m = screen_reply(msg["content"], policy, vault)
                masked |= m
        self.account(
            model,
            name,
            event,
            t0,
            usage_of(reply),
            {"masked_out": masked} if masked else {},
        )
        self.send_json(200, reply)

    def stream(self, model, body, policy, name, event, t0):
        """SSE pass-through. ponytail: chunks are not restored/masked (a token can split
        across chunks); buffer per choice if streamed replies must be screened too."""
        if not (resp := self.call(model, body, event)):
            return
        usage, done = (0, 0), False
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        with resp:
            for line in resp:
                if line.startswith(b"data: {"):
                    try:
                        usage = (
                            usage_of(json.loads(line[6:]))
                            if b'"usage"' in line
                            else usage
                        )
                    except ValueError:
                        pass
                if line.startswith(b"data: [DONE]") and not done:  # account before the client may hang up
                    done = self.account(model, name, event, t0, usage, {"stream": True}) or True
                self.wfile.write(line)
                self.wfile.flush()
        if not done:
            self.account(model, name, event, t0, usage, {"stream": True})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guard-gateway")
    ap.add_argument("--listen", default="127.0.0.1:8787")
    args = ap.parse_args(argv)
    host, port = args.listen.rsplit(":", 1)
    match load(POLICY):
        case Err(e):
            print(f"guard gateway: {e.detail}", file=sys.stderr)
            return 1
        case Ok(policy):
            demo = {n for n, p in policy.gateway.principals.items() if p.key_sha256 == DEMO_KEY_SHA256}
    if demo and host not in ("127.0.0.1", "localhost", "::1"):
        print(f"guard gateway: principal(s) {sorted(demo)} use the published demo key; "
              f"set a real key_sha256 before listening on {host}", file=sys.stderr)
        return 1
    srv = ThreadingHTTPServer((host, int(port)), Handler)
    print(f"guard gateway on http://{host}:{port}/v1  (policy {POLICY})", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
