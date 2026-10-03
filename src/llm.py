"""OpenAI-compatible provider boundary, shared by apps that call LLMs/embeddings.

SDK exceptions become ProviderError data here; the SDK's types never leave this module.
Classification only: retry/fallback is decided by the calling app. The SDK client's own
max_retries (default 2) is the only retry layer today; build it with max_retries=0 before
adding app-level retries, or attempts multiply.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

import numpy as np
import openai

from src.result import Err, Ok, Result, attempt

type Kind = Literal[
    "timeout", "unavailable", "rate_limited", "auth", "rejected", "malformed"
]
TRANSIENT: frozenset[Kind] = frozenset({"timeout", "unavailable", "rate_limited"})


@dataclass(frozen=True, slots=True)
class ProviderError:
    op: str
    kind: Kind
    detail: str = ""
    status: int | None = None


def to_provider_error(op: str, e: Exception) -> ProviderError:
    status = getattr(e, "status_code", None)
    match e:
        # order matters: APITimeoutError subclasses APIConnectionError
        case openai.APITimeoutError():
            kind = "timeout"
        case openai.APIConnectionError():
            kind = "unavailable"
        case openai.APIStatusError(status_code=429):
            kind = "rate_limited"
        case openai.APIStatusError(status_code=401 | 403):
            kind = "auth"
        case openai.APIStatusError(status_code=s) if s == 408 or s >= 500:
            kind = "unavailable"
        case openai.APIStatusError():
            kind = "rejected"
        case _:  # e.g. APIResponseValidationError: the server answered nonsense
            kind = "malformed"
    return ProviderError(op, kind, str(e), status)


def call_provider[T](op: str, f: Callable[[], T]) -> Result[T, ProviderError]:
    """Run one SDK call; only openai.APIError becomes Err, bugs propagate."""
    return attempt(f, (openai.APIError,), lambda e: to_provider_error(op, e))


@dataclass(frozen=True, slots=True)
class Completion:
    text: str
    model: str
    input_tokens: int | None  # None: the server did not report usage
    output_tokens: int | None


type Complete = Callable[..., Result[Completion, ProviderError]]


def completer(client: openai.OpenAI, model: str) -> Complete:
    """messages (+ SDK kwargs such as response_format) -> Completion with usage."""

    def complete(messages: list, **kw) -> Result[Completion, ProviderError]:
        return call_provider(
            "generate",
            lambda: client.chat.completions.create(
                model=model, messages=messages, **kw
            ),
        ).bind(completion_of)

    return complete


def completion_of(resp) -> Result[Completion, ProviderError]:
    content = resp.choices[0].message.content if resp.choices else None
    if not content:  # refusal / tool call / truncated by some servers: not an answer
        return Err(ProviderError("generate", "malformed", "empty completion"))
    u = getattr(resp, "usage", None)
    return Ok(
        Completion(
            content,
            resp.model,
            getattr(u, "prompt_tokens", None),
            getattr(u, "completion_tokens", None),
        )
    )


type Embed = Callable[[Sequence[str]], Result[np.ndarray, ProviderError]]


def embedder(client: openai.OpenAI, model: str, batch: int = 100) -> Embed:
    """Texts -> (n, dim) float32 unit rows, in input order. Zero vectors stay zero (no NaN)."""

    def embed(texts: Sequence[str]) -> Result[np.ndarray, ProviderError]:
        if not texts:  # the API rejects empty input; nothing to do
            return Ok(np.zeros((0, 0), np.float32))
        rows: list[list[float]] = []
        for i in range(0, len(texts), batch):
            chunk = list(texts[i : i + batch])
            match call_provider(
                "embed", lambda: client.embeddings.create(model=model, input=chunk)
            ):
                case Err() as err:
                    return err
                case Ok(resp):
                    data = sorted(resp.data, key=lambda d: d.index)
                    # per batch: a short/long batch would shift vectors onto wrong texts
                    if [d.index for d in data] != list(range(len(chunk))):
                        return Err(
                            ProviderError("embed", "malformed", "batch index mismatch")
                        )
                    rows += [d.embedding for d in data]
        return unit_rows(rows, len(texts))

    return embed


def unit_rows(rows: list[list[float]], n: int) -> Result[np.ndarray, ProviderError]:
    if len(rows) != n or len({len(r) for r in rows}) != 1:
        return Err(
            ProviderError("embed", "malformed", f"expected {n} equal-length vectors")
        )
    v = np.asarray(rows, dtype=np.float32)
    if not np.isfinite(v).all():
        return Err(ProviderError("embed", "malformed", "non-finite vector"))
    norm = np.linalg.norm(v, axis=1, keepdims=True)
    return Ok(np.divide(v, norm, out=np.zeros_like(v), where=norm > 0))
