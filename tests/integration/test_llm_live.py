"""Live provider calls through src/llm.py. Key comes from sops: `sops decrypt secrets.env > .env`.

  uv run --env-file .env pytest -m "integration and live_api" -s
"""

import os

import numpy as np
import pytest

from src.result import Ok

pytestmark = [
    pytest.mark.integration,
    pytest.mark.live_api,
    pytest.mark.skipif(not os.environ.get("OPENAI_API_KEY"), reason="needs .env (OPENAI_API_KEY)"),
]


def test_embedding_endpoint_returns_unit_rows(say):
    from openai import OpenAI

    from src.llm import embedder

    model = os.environ.get("EMBED_MODEL", "text-embedding-3-small")
    say.title(f"Embeddingi przez src/llm.py ({model})")
    r = embedder(OpenAI(), model)(["rampa dla wózka", "schody bez poręczy"])
    assert isinstance(r, Ok), r
    say.ok(f"kształt {r.value.shape}, normy {np.linalg.norm(r.value, axis=1).round(3).tolist()}")
    assert r.value.shape[0] == 2
    np.testing.assert_allclose(np.linalg.norm(r.value, axis=1), 1, rtol=1e-5)
