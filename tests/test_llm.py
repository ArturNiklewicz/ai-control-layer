"""Contract tests for the provider boundary: real openai exception classes, fake client."""

from types import SimpleNamespace as NS

from typing import Any, cast

import httpx2 as httpx  # the transport openai 3.x is built on
import numpy as np
import openai
import pytest

from src.llm import (
    Completion,
    ProviderError,
    call_provider,
    completer,
    embedder,
    to_provider_error,
)
from src.result import Err, Ok

REQ = httpx.Request("POST", "http://llm.test/v1/x")


def status_error(cls, code):
    return cls("boom", response=httpx.Response(code, request=REQ), body=None)


@pytest.mark.parametrize(
    "exc, kind",
    [
        (
            openai.APITimeoutError(request=REQ),
            "timeout",
        ),  # subclass of connection error
        (openai.APIConnectionError(request=REQ), "unavailable"),
        (status_error(openai.RateLimitError, 429), "rate_limited"),
        (status_error(openai.AuthenticationError, 401), "auth"),
        (status_error(openai.PermissionDeniedError, 403), "auth"),
        (status_error(openai.InternalServerError, 503), "unavailable"),
        (status_error(openai.APIStatusError, 408), "unavailable"),
        (status_error(openai.BadRequestError, 400), "rejected"),
        (status_error(openai.UnprocessableEntityError, 422), "rejected"),
        (
            openai.APIResponseValidationError(httpx.Response(200, request=REQ), None),
            "malformed",
        ),
    ],
)
def test_sdk_errors_are_classified(exc, kind):
    assert to_provider_error("op", exc).kind == kind
    assert call_provider("op", lambda: (_ for _ in ()).throw(exc)) == Err(
        to_provider_error("op", exc)
    )


def test_bugs_are_not_provider_errors():
    with pytest.raises(TypeError):
        call_provider("op", lambda: None + 1)  # type: ignore[operator]


def fake_client(embeddings) -> Any:
    return cast(Any, NS(embeddings=embeddings))


class FakeEmbeddings:
    def __init__(self, dim=3, drop=0):
        self.calls, self.dim, self.drop = [], dim, drop

    def create(self, model, input):
        self.calls.append(list(input))
        data = [
            NS(index=i, embedding=[float(len(t))] + [1.0] * (self.dim - 1))
            for i, t in enumerate(input)
        ][self.drop :]
        return NS(data=list(reversed(data)))  # API may return any order


def test_embedder_batches_orders_and_normalizes():
    fake = FakeEmbeddings()
    r = embedder(fake_client(fake), "m", batch=2)(["a", "bb", "ccc", "dddd", "e"])
    assert [len(c) for c in fake.calls] == [2, 2, 1]
    assert isinstance(r, Ok)
    assert r.value.shape == (5, 3)
    np.testing.assert_allclose(np.linalg.norm(r.value, axis=1), 1, rtol=1e-6)
    assert r.value[3, 0] > r.value[0, 0]  # input order kept despite reversed data


def test_embedder_empty_input_skips_api():
    fake = FakeEmbeddings()
    assert embedder(fake_client(fake), "m")([]).value.shape[0] == 0  # type: ignore[union-attr]
    assert fake.calls == []


def test_embedder_count_mismatch_is_malformed():
    r = embedder(fake_client(FakeEmbeddings(drop=1)), "m")(["a", "b"])
    assert isinstance(r, Err) and r.error.kind == "malformed"


def test_embedder_zero_vector_stays_finite():
    class Zero:
        def create(self, model, input):
            return NS(data=[NS(index=0, embedding=[0.0, 0.0])])

    r = embedder(fake_client(Zero()), "m")(["x"])
    assert isinstance(r, Ok) and not np.isnan(r.value).any()


def test_embedder_stops_at_first_failed_batch():
    class Down:
        calls = 0

        def create(self, model, input):
            Down.calls += 1
            raise openai.APIConnectionError(request=REQ)

    r = embedder(fake_client(Down()), "m", batch=1)(["a", "b"])
    assert r == Err(ProviderError("embed", "unavailable", "Connection error."))
    assert Down.calls == 1


def test_embedder_rejects_per_batch_shift_even_if_total_matches():
    class Shifty:  # batch 1 returns 3 rows, batch 2 returns 1: total still 4
        def create(self, model, input):
            n = 3 if input[0] == "a" else 1
            return NS(data=[NS(index=i, embedding=[1.0, 0.0]) for i in range(n)])

    r = embedder(fake_client(Shifty()), "m", batch=2)(["a", "b", "c", "d"])
    assert isinstance(r, Err) and r.error.kind == "malformed"


def test_embedder_rejects_non_finite():
    class Inf:
        def create(self, model, input):
            return NS(data=[NS(index=0, embedding=[float("inf"), 0.0])])

    r = embedder(fake_client(Inf()), "m")(["x"])
    assert isinstance(r, Err) and r.error.kind == "malformed"


def fake_chat_client(resp) -> Any:
    return cast(Any, NS(chat=NS(completions=NS(create=lambda **kw: resp))))


def test_completer_returns_text_and_usage():
    resp = NS(
        model="m",
        choices=[NS(message=NS(content="hi"))],
        usage=NS(prompt_tokens=7, completion_tokens=2),
    )
    r = completer(fake_chat_client(resp), "m")([{"role": "user", "content": "x"}])
    assert r == Ok(Completion("hi", "m", 7, 2))


@pytest.mark.parametrize("choices", [[], [NS(message=NS(content=None))]])
def test_empty_completion_is_malformed_not_ok_none(choices):
    r = completer(fake_chat_client(NS(model="m", choices=choices)), "m")([])
    assert isinstance(r, Err) and r.error.kind == "malformed"
