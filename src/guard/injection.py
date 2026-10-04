"""Untrusted-text screening: prompt injection, exfiltration, known exploit signatures.

Deterministic signatures come from a replaceable feed (JSON); loading is the only I/O.
Matching is pure. Content that passes is still untrusted data, never instructions.
"""

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from src.result import Result, attempt


@dataclass(frozen=True, slots=True)
class Signature:
    id: str
    category: str
    severity: str  # high | medium | low
    source: str
    pattern: re.Pattern


@dataclass(frozen=True, slots=True)
class Hit:
    id: str
    category: str
    severity: str


@dataclass(frozen=True, slots=True)
class FeedError:
    detail: str


def parse_feed(raw: dict) -> Result[tuple[Signature, ...], FeedError]:
    def build() -> tuple[Signature, ...]:
        return tuple(
            Signature(
                s["id"],
                s["category"],
                s["severity"],
                s.get("source", ""),
                re.compile(s["pattern"], re.M),
            )
            for s in raw["signatures"]
        )

    return attempt(
        build,
        (KeyError, TypeError, re.error),
        lambda e: FeedError(f"bad signature feed: {e!r}"),
    )


def load_feed(path: Path) -> Result[tuple[Signature, ...], FeedError]:
    return attempt(
        lambda: json.loads(path.read_text()),
        (OSError, ValueError),
        lambda e: FeedError(f"{path}: {e}"),
    ).bind(parse_feed)


def normalize(text: str) -> str:
    """Defeat cheap obfuscation (full-width letters, ligatures) before matching."""
    return unicodedata.normalize("NFKC", text)


_JSON_ESC = re.compile(r"\\([nrtbf\"'\\/])")
_ESCAPED = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", '"': '"', "'": "'", "\\": "\\", "/": "/"}


def unescape(text: str) -> str:
    """Decode literal JSON escapes. Tool results ride to the hook as JSON strings, so their
    newlines are two-char `\\n` sequences: `\\nIgnore` has no word boundary before `Ignore`
    and \\b-anchored signatures miss it. Screening must see the prose the model will read."""
    return _JSON_ESC.sub(lambda m: _ESCAPED[m.group(1)], text)


def scan(text: str, feed: tuple[Signature, ...]) -> list[Hit]:
    # raw text too: NFKC can erase the hidden characters some signatures look for
    variants = {text, normalize(text), unescape(text)}
    return [
        Hit(s.id, s.category, s.severity)
        for s in feed
        if any(s.pattern.search(v) for v in variants)
    ]


def worst(hits: list[Hit]) -> str | None:
    order = ("high", "medium", "low")
    return next((sev for sev in order if any(h.severity == sev for h in hits)), None)

