"""Anthropic Messages proxy: nothing personal leaves, originals come back, history stays stable.

Fake upstream on loopback records exactly what would have reached api.anthropic.com; the local
model is faked by a function that "recognises" a fixed set of names, like NER would.
"""

import copy
import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.guard import gateway
from src.guard.anonymizer import Anonymizer, holdback
from src.guard.anthropic import StreamRestorer, strings, walk
from src.guard.policy import parse
from src.result import Ok
from tests.guard_fixtures import RAW

NAMES = {
    "Jan Kowalski": "Jan Kowalski",
    "Jana Kowalskiego": "Jan Kowalski",
    "Kasią": "Kasia",
    "John Smith": "John Smith",
}


def fake_ner(messages, **kw):
    doc = messages[-1]["content"]
    found = [
        {"type": "PERSON", "text": t, "canonical": c}
        for t, c in NAMES.items()
        if t in doc
    ]
    if "ul. Lipowa 5" in doc:
        found.append(
            {"type": "ADDRESS", "text": "ul. Lipowa 5", "canonical": "ul. Lipowa 5"}
        )
    return Ok(json.dumps({"entities": found}))


def policy_raw():
    raw = copy.deepcopy(RAW)
    raw["gateway"]["anthropic"] = {
        "upstream": "http://placeholder",
        "models": ["claude-*"],
    }
    return raw


POLICY = parse(policy_raw()).value  # type: ignore[union-attr]


# --- engine ---


def test_names_without_rules_are_pseudonymized_per_person_and_spelling(tmp_path):
    eng = Anonymizer(tmp_path / "s.json", fake_ner)
    texts = [
        "Jan Kowalski mieszka na ul. Lipowa 5",
        "Spotkałem Jana Kowalskiego i Kasią",
        "PESEL 44051401359",
    ]
    out, counts, _ = eng.pseudonymize_many(texts, POLICY).value  # type: ignore[union-attr]
    assert out[texts[0]] == "[OSOBA_1] mieszka na [ADRES_1]"
    assert (
        out[texts[1]] == "Spotkałem [OSOBA_1.2] i [OSOBA_2]"
    )  # same person, other spelling
    assert out[texts[2]] == "PESEL [PESEL_1]"
    assert counts == {"PERSON": 3, "ADDRESS": 1, "PESEL": 1}
    assert (
        eng.restore(out[texts[1]]) == texts[1]
    )  # exact spelling back, not the nominative


def test_allow_list_secrets_and_emails_are_not_reversible(tmp_path):
    eng = Anonymizer(
        None,
        lambda m, **kw: Ok(
            json.dumps(
                {
                    "entities": [
                        {"type": "PERSON", "text": "Claude", "canonical": "Claude"}
                    ]
                }
            )
        ),
    )
    t = "Claude, key AKIAIOSFODNN7EXAMPLE, mail a@b.pl"
    out = eng.pseudonymize_many([t], POLICY).value[0][t]  # type: ignore[union-attr]
    assert out == "Claude, key [SECRET], mail [EMAIL]"
    assert eng.restore(out) == out


def test_model_down_fails_closed_and_cache_avoids_repeat_calls(tmp_path):
    from src.result import Err

    calls = []
    eng = Anonymizer(
        tmp_path / "s.json", lambda m, **kw: calls.append(1) or fake_ner(m)
    )
    eng.pseudonymize_many(["Jan Kowalski"], POLICY)
    eng.pseudonymize_many(["Jan Kowalski"], POLICY)
    assert len(calls) == 1
    down = Anonymizer(None, lambda m, **kw: Err("timeout"))
    assert "nothing was sent" in down.pseudonymize_many(["Jan Kowalski"], POLICY).error  # type: ignore[union-attr]
    assert down.pseudonymize_many(["12345"], POLICY).value[0] == {"12345": "12345"}  # type: ignore[union-attr]  # no letters: no model


def test_state_survives_restart(tmp_path):
    a = Anonymizer(tmp_path / "s.json", fake_ner)
    out = a.pseudonymize_many(["Kasią"], POLICY).value[0]["Kasią"]  # type: ignore[union-attr]
    a.save()
    b = Anonymizer(
        tmp_path / "s.json", lambda m, **kw: pytest.fail("cache miss after restart")
    )
    assert b.pseudonymize_many(["Kasią"], POLICY).value[0]["Kasią"] == out  # type: ignore[union-attr]
    assert b.restore(out) == "Kasią"


def test_holdback_never_splits_a_token():
    assert holdback("Hello [OSO") == 6
    assert holdback("Hello [OSOBA_1") == 6
    assert holdback("Hello [OSOBA_1.") == 6
    assert holdback("Hello [OSOBA_1]") == 15
    assert holdback("array[0") == 5 or holdback("array[0") == 7  # harmless either way


# --- request walk ---


def test_walk_skips_ids_thinking_media_and_tool_definitions():
    body = {
        "model": "claude-x",
        "system": [{"type": "text", "text": "S"}],
        "tools": [{"name": "Read", "description": "D"}],
        "messages": [
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "T", "signature": "sig"},
                {"type": "tool_use", "id": "toolu_1", "name": "Write", "input": {"file_path": "a.txt", "content": "C"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "R"}]},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "B64"}},
                {"type": "text", "text": "U"},
            ]},
        ],
    }  # fmt: skip
    assert sorted(strings(body)) == ["C", "R", "S", "U", "a.txt"]
    assert walk(body, str.lower)["messages"][0]["content"][0]["thinking"] == "T"


# --- streaming ---


def sse_events(reply_parts: list[str]):
    yield (
        "message_start",
        {"type": "message_start", "message": {"usage": {"input_tokens": 10}}},
    )
    yield (
        "content_block_start",
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "text", "text": ""},
        },
    )
    for p in reply_parts:
        yield (
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": p},
            },
        )
    yield "content_block_stop", {"type": "content_block_stop", "index": 0}
    yield (
        "message_delta",
        {"type": "message_delta", "delta": {}, "usage": {"output_tokens": 5}},
    )


def test_stream_restores_tokens_split_across_deltas(tmp_path):
    eng = Anonymizer(None, fake_ner)
    eng.pseudonymize_many(["Jana Kowalskiego"], POLICY)
    remembered = {}
    sr = StreamRestorer(
        eng.restore, eng.restore, lambda a, b: remembered.__setitem__(a, b)
    )
    out = [
        e
        for n, d in sse_events(["Dotyczy [OS", "OBA_1", "] i nikogo więcej"])
        for e in sr.event(n, d)
    ]
    text = "".join(d["delta"]["text"] for n, d in out if n == "content_block_delta")
    assert text == "Dotyczy Jana Kowalskiego i nikogo więcej"
    assert remembered == {text: "Dotyczy [OSOBA_1] i nikogo więcej"}
    assert sr.usage == [10, 5]


# --- HTTP: client -> proxy -> fake api.anthropic.com ---


class FakeAnthropic(BaseHTTPRequestHandler):
    seen: list[tuple[dict, dict]] = []

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeAnthropic.seen.append(({k.lower(): v for k, v in self.headers.items()}, body))
        last = body["messages"][-1]["content"]
        text = last if isinstance(last, str) else last[-1]["text"]
        reply = "Echo: " + text
        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            parts = [
                reply[i : i + 4] for i in range(0, len(reply), 4)
            ]  # splits tokens on purpose
            for n, d in sse_events(parts):
                self.wfile.write(f"event: {n}\ndata: {json.dumps(d)}\n\n".encode())
            return
        data = json.dumps({"type": "message", "role": "assistant", "content": [{"type": "text", "text": reply}],
                           "usage": {"input_tokens": 10, "output_tokens": 5}}).encode()  # fmt: skip
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    up, up_url = serve(FakeAnthropic)
    FakeAnthropic.seen = []
    raw = policy_raw()
    raw["gateway"]["anthropic"]["upstream"] = up_url
    pol = parse(raw).value  # type: ignore[union-attr]
    monkeypatch.setattr(gateway, "load", lambda path: Ok(pol))
    monkeypatch.setattr(gateway, "ROOT", tmp_path)
    monkeypatch.setattr(gateway, "engine", lambda policy: ENGINE)
    ENGINE = Anonymizer(tmp_path / "state.json", fake_ner)
    srv, url = serve(gateway.Handler)
    yield url, tmp_path
    srv.shutdown()
    up.shutdown()


def post(url: str, body: dict, path="/v1/messages?beta=true") -> tuple[int, bytes]:
    req = urllib.request.Request(url + path, json.dumps(body).encode(), method="POST", headers={
        "Content-Type": "application/json", "x-api-key": "sk-ant-test", "anthropic-version": "2023-06-01",
        "anthropic-beta": "oauth-2025-04-20"})  # fmt: skip
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


PROMPT = "Napisz do Jana Kowalskiego (PESEL 44051401359), ul. Lipowa 5"


def test_nothing_personal_reaches_upstream_and_reply_is_restored(proxy):
    url, root = proxy
    status, data = post(
        url,
        {
            "model": "claude-sonnet-x",
            "max_tokens": 50,
            "messages": [{"role": "user", "content": PROMPT}],
        },
    )
    headers, sent = FakeAnthropic.seen[-1]
    wire = json.dumps(sent, ensure_ascii=False)
    assert status == 200
    for secret in ("Kowalsk", "44051401359", "Lipowa"):
        assert secret not in wire
    assert (
        headers["x-api-key"] == "sk-ant-test"
        and headers["anthropic-beta"] == "oauth-2025-04-20"
    )
    assert json.loads(data)["content"][0]["text"] == "Echo: " + PROMPT
    e = [
        json.loads(line)
        for line in (root / ".guard/audit.jsonl").read_text().splitlines()
    ][-1]
    assert e["api"] == "anthropic" and e["pii"] == {
        "PERSON": 1,
        "PESEL": 1,
        "ADDRESS": 1,
    }


def test_streamed_reply_restored_and_next_turn_resends_identical_history(proxy):
    url, _ = proxy
    turn1 = {
        "model": "claude-x",
        "stream": True,
        "max_tokens": 50,
        "messages": [{"role": "user", "content": PROMPT}],
    }
    status, data = post(url, turn1)
    deltas = [
        json.loads(line[5:])
        for line in data.decode().splitlines()
        if line.startswith("data:")
    ]
    text = "".join(
        d["delta"]["text"] for d in deltas if d.get("type") == "content_block_delta"
    )
    assert status == 200 and text == "Echo: " + PROMPT
    model_saw = FakeAnthropic.seen[-1][1]["messages"][0]["content"]
    # turn 2: the client resends history with the restored assistant text
    turn2 = turn1 | {"messages": turn1["messages"] + [{"role": "assistant", "content": [{"type": "text", "text": text}]},
                                                     {"role": "user", "content": "dzięki"}]}  # fmt: skip
    post(url, turn2)
    hist = FakeAnthropic.seen[-1][1]["messages"]
    assert hist[0]["content"] == model_saw
    assert (
        hist[1]["content"][0]["text"] == "Echo: " + model_saw
    )  # byte-identical to what the model wrote


def test_model_not_allowed_and_count_tokens(proxy):
    url, _ = proxy
    status, data = post(
        url, {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}
    )
    assert status == 403 and b"model-denied" in data
    assert FakeAnthropic.seen == []
    status, _ = post(
        url,
        {"model": "claude-x", "messages": [{"role": "user", "content": PROMPT}]},
        "/v1/messages/count_tokens",
    )
    assert "Kowalsk" not in json.dumps(FakeAnthropic.seen[-1][1], ensure_ascii=False)


def test_reply_restores_only_this_requests_tokens(proxy):
    # regression: the vault is shared, so a caller who typed "[OSOBA_1]" got someone's name back
    url, _ = proxy
    post(url, {"model": "claude-x", "max_tokens": 50, "messages": [{"role": "user", "content": PROMPT}]})
    status, data = post(url, {"model": "claude-x", "max_tokens": 50, "messages": [{"role": "user", "content": "kim jest [OSOBA_1]?"}]})
    assert status == 200 and "Kowalsk" not in data.decode()


def test_metadata_and_urls_are_screened():
    # regression: metadata, url and citations were skipped as if they were identifiers
    body = {"metadata": {"user_id": "u"}, "messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "url", "url": "https://x/u"}, "citations": {"enabled": True}}]}]}  # fmt: skip
    assert sorted(strings(body)) == ["https://x/u", "u"]
