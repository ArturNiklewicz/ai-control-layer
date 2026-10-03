"""Anthropic Messages API shape: which strings leave the machine, and how replies come back.

Pure functions over request/response bodies and SSE events; the HTTP shell is in gateway.py.
Skipped on purpose: identifiers (ids, names, model, media types), base64 media, and thinking
blocks (signed by the API; they only ever contain what the model saw, i.e. pseudonyms).
"""

import json
from collections.abc import Callable
from typing import Any

from src.guard.anonymizer import holdback

# identifiers only: anything that can hold free text (metadata, urls, citations) is screened
SKIP_KEYS = frozenset({
    "type", "id", "tool_use_id", "name", "model", "signature", "media_type", "cache_control", "role", "stop_reason",
})  # fmt: skip
OPAQUE_BLOCKS = frozenset({"thinking", "redacted_thinking", "image"})
# the harness's own tool definitions: static, no user data, and rewriting them changes behaviour.
# ponytail: MCP tool descriptions come from servers too; screen them if a server can carry data
SKIP_SUBTREES = frozenset({"tools"})


def walk(value, f: Callable[[str], str], key: str = "") -> Any:
    """f over every outgoing string. ponytail: dict keys pass (tool schema / argument names)."""
    if isinstance(value, str):
        return value if key in SKIP_KEYS else f(value)
    if isinstance(value, list):
        return [walk(v, f, key) for v in value]
    if isinstance(value, dict):
        if value.get("type") in OPAQUE_BLOCKS or value.get("type") == "base64":
            return value
        return {k: v if k in SKIP_SUBTREES else walk(v, f, k) for k, v in value.items()}
    return value


def strings(value) -> list[str]:
    out: list[str] = []
    walk(value, lambda s: out.append(s) or s)
    return out


def pairs(restored, sent):
    """Leaf strings of two same-shaped JSON values, side by side."""
    if isinstance(restored, str) and isinstance(sent, str):
        yield restored, sent
    elif isinstance(restored, list) and isinstance(sent, list):
        for a, b in zip(restored, sent):
            yield from pairs(a, b)
    elif isinstance(restored, dict) and isinstance(sent, dict):
        for k in restored.keys() & sent.keys():
            yield from pairs(restored[k], sent[k])


def restore_reply(
    reply: dict, restore: Callable[[str], str], remember: Callable[[str, str], None]
) -> dict:
    """Non-streamed response: originals back into text and tool inputs; memo for the next turn."""
    for block in reply.get("content") or []:
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            sent = block["text"]
            block["text"] = restore(sent)
            remember(block["text"], sent)
        elif block.get("type") == "tool_use":
            sent = block.get("input")
            block["input"] = walk(sent, restore)
            for a, b in pairs(block["input"], sent):
                remember(a, b)
    return reply


class StreamRestorer:
    """SSE events in, SSE events out. Text and tool-input deltas are restored; a token split
    across deltas is held back until complete; the rest passes byte-identical."""

    def __init__(
        self,
        restore: Callable[[str], str],
        restore_json: Callable[[str], str],
        remember: Callable[[str, str], None],
    ):
        self.restore, self.restore_json, self.remember = restore, restore_json, remember
        self.kind: dict[int, str] = {}  # index -> "text" | "tool_use" | other
        self.pending: dict[int, str] = {}  # model text not yet emitted
        self.full: dict[int, str] = {}  # model text so far (memo at block stop)
        self.usage = [0, 0]

    def delta(self, i: int, piece: str, final: bool = False) -> str:
        buf = self.pending.get(i, "") + piece
        cut = len(buf) if final else holdback(buf)
        self.pending[i] = buf[cut:]
        self.full[i] = self.full.get(i, "") + piece
        return buf[:cut]

    def event(self, name: str, data: dict) -> list[tuple[str, dict]]:
        i = data.get("index", -1)
        if name == "message_start":
            u = (data.get("message") or {}).get("usage") or {}
            self.usage[0] = (
                int(u.get("input_tokens") or 0)
                + int(u.get("cache_read_input_tokens") or 0)
                + int(u.get("cache_creation_input_tokens") or 0)
            )
        elif name == "message_delta":
            self.usage[1] = int(
                (data.get("usage") or {}).get("output_tokens") or self.usage[1]
            )
        elif name == "content_block_start":
            self.kind[i] = (data.get("content_block") or {}).get("type", "")
        elif name == "content_block_delta":
            d = data.get("delta") or {}
            if d.get("type") == "text_delta":
                out = self.delta(i, d.get("text", ""))
                return (
                    [(name, data | {"delta": d | {"text": self.restore(out)}})]
                    if out
                    else []
                )
            if d.get("type") == "input_json_delta":
                out = self.delta(i, d.get("partial_json", ""))
                return (
                    [
                        (
                            name,
                            data
                            | {"delta": d | {"partial_json": self.restore_json(out)}},
                        )
                    ]
                    if out
                    else []
                )
        elif name == "content_block_stop":
            return self.flush(i) + [(name, data)]
        return [(name, data)]

    def flush(self, i: int) -> list[tuple[str, dict]]:
        kind, rest = self.kind.get(i), self.delta(i, "", final=True)
        out = []
        if rest and kind == "text":
            out.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {"type": "text_delta", "text": self.restore(rest)},
                    },
                )
            )
        elif rest and kind == "tool_use":
            out.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": i,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": self.restore_json(rest),
                        },
                    },
                )
            )
        model = self.full.pop(i, "")
        if kind == "text":
            self.remember(self.restore(model), model)
        elif kind == "tool_use" and model:
            try:
                for a, b in pairs(
                    json.loads(self.restore_json(model)), json.loads(model)
                ):
                    self.remember(a, b)
            except ValueError:
                pass  # malformed tool JSON: the client will fail on it too
        return out


def sse(name: str, data: dict) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode()
