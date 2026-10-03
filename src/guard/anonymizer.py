"""Anonymization engine shared by the proxy, the gateway and the CLI.

Detection = checksummed regexes + the local model (NER) on every text that has letters: names
and addresses have no reliable rules. Results are cached by text hash, so a conversation that
is resent every turn is analysed once; uncached chunks go to the model in parallel.

Tokens are per person and per spelling: "Jan Kowalski" -> [OSOBA_1], "Jana Kowalskiego" ->
[OSOBA_1.2]. Same number = same person for the model; restore returns the exact spelling,
so an agent's Edit(old_string="[OSOBA_1.2]") still matches the file.

State (vault, span cache, restore memo) lives in a host-only file the sandbox never mounts.
"""

import hashlib
import json
import os
import re
import threading
from collections import Counter
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from src.guard.pii import (
    PRIORITY,
    SEMANTIC_SCHEMA,
    SEMANTIC_SYSTEM,
    Span,
    chunks,
    detect,
    label,
    locate,
    non_overlapping,
    parse_entities,
)
from src.guard.policy import Policy
from src.result import Err, Ok, Result

type Complete = Callable[..., Result[str, object]]

HAS_WORD = re.compile(r"[^\W\d_]{2}")  # no two adjacent letters = no name, no address
TOKEN = re.compile(r"\[([A-Z_]+_\d+(?:\.\d+)?)\]")
PARTIAL = re.compile(r"\[[A-Z_]*(?:_\d*)?(?:\.\d*)?$")  # a token cut by a stream chunk
SEMANTIC_PRIORITY = PRIORITY | {"PERSON": 90, "ADDRESS": 91}
POOL = ThreadPoolExecutor(16)  # vLLM batches concurrent requests


def holdback(text: str) -> int:
    """How much of a streamed buffer is safe to emit: everything before an unfinished token."""
    m = PARTIAL.search(text)
    return m.start() if m and len(text) - m.start() <= 32 else len(text)


@dataclass
class Vault:
    """token -> exact spelling; (label, canonical) -> person number; spellings per person."""

    tokens: dict[str, str] = field(default_factory=dict)
    person: dict[tuple[str, str], int] = field(default_factory=dict)
    spelling: dict[tuple[str, str, str], str] = field(default_factory=dict)

    def token(self, kind_label: str, canonical: str, surface: str) -> str:
        if (t := self.spelling.get((kind_label, canonical, surface))) is None:
            n = self.person.setdefault(
                (kind_label, canonical),
                1 + sum(1 for k in self.person if k[0] == kind_label),
            )
            k = 1 + sum(1 for s in self.spelling if s[:2] == (kind_label, canonical))
            t = f"{kind_label}_{n}" + (f".{k}" if k > 1 else "")
            self.spelling[(kind_label, canonical, surface)] = t
            self.tokens[t] = surface
        return t

    def dump(self) -> list:
        return [
            [lab, canon, surface, t]
            for (lab, canon, surface), t in self.spelling.items()
        ]

    @classmethod
    def load(cls, rows: Iterable) -> "Vault":
        v = cls()
        for lab, canon, surface, t in rows:
            v.spelling[(lab, canon, surface)] = t
            v.tokens[t] = surface
            v.person.setdefault((lab, canon), int(t.split("_")[-1].split(".")[0]))
        return v


def restore(text: str, vault: Vault, escape: Callable[[str], str] = str) -> str:
    return TOKEN.sub(
        lambda m: escape(vault.tokens[m[1]]) if m[1] in vault.tokens else m[0], text
    )


def json_escape(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)[1:-1]


def entities_of(chunk: str, complete: Complete) -> Result[list, object]:
    messages = [
        {"role": "system", "content": SEMANTIC_SYSTEM},
        {"role": "user", "content": f"<document>\n{chunk}\n</document>"},
    ]
    return complete(messages, response_format=SEMANTIC_SCHEMA, temperature=0).bind(
        parse_entities
    )


class Anonymizer:
    """Thread-safe; one per process. `complete` = the local model (None: regex only)."""

    def __init__(
        self, path: Path | None, complete: Complete | None, fail_closed: bool = True
    ):
        self.path, self.complete, self.fail_closed = path, complete, fail_closed
        self.lock = threading.Lock()
        self.vault, self.spans, self.memo = Vault(), {}, {}
        if path and path.is_file():
            try:
                s = json.loads(path.read_text())
                self.vault = Vault.load(s.get("vault", []))
                self.spans = {
                    k: [Span(a, b, kind, "", c) for a, b, kind, c in v]
                    for k, v in s.get("spans", {}).items()
                }
                self.memo = s.get("memo", {})
            except (ValueError, TypeError, KeyError) as e:
                raise RuntimeError(
                    f"{path}: unreadable anonymizer state ({e!r}); move it aside"
                ) from e

    # --- detection ---

    def detect_many(self, texts: Iterable[str]) -> Result[dict[str, list[Span]], str]:
        """Spans for every distinct text: cached, else regex + model (chunks in parallel)."""
        todo = {hashlib.sha256(t.encode()).hexdigest(): t for t in texts}
        with self.lock:
            missing = {h: t for h, t in todo.items() if h not in self.spans}
        if missing:
            jobs = [
                (h, POOL.submit(entities_of, c, self.complete))
                for h, t in missing.items() if self.complete and HAS_WORD.search(t)
                for _, c in chunks(t)
            ]  # fmt: skip
            entities: dict[str, list] = {h: [] for h in missing}
            for h, job in jobs:
                match job.result():
                    case Ok(found):
                        entities[h] += found
                    case Err(e) if self.fail_closed:
                        return Err(f"semantic detector failed ({e}); nothing was sent")
                    case Err():
                        pass  # regex_only policy
            found = {
                h: non_overlapping(
                    detect(t) + locate(t, entities[h]), SEMANTIC_PRIORITY
                )
                for h, t in missing.items()
            }
            with self.lock:
                self.spans |= {
                    h: [Span(s.start, s.end, s.kind, "", s.canonical) for s in v]
                    for h, v in found.items()
                }
        with self.lock:
            return Ok({t: [Span(s.start, s.end, s.kind, t[s.start : s.end], s.canonical) for s in self.spans[h]]
                       for h, t in todo.items()})  # fmt: skip

    # --- transform ---

    def mask(
        self, text: str, spans: list[Span], policy: Policy, counts: Counter
    ) -> str:
        out, last = [], 0
        for s in non_overlapping(spans, SEMANTIC_PRIORITY):
            action = policy.action(s.kind)
            if (
                action == "off"
                or s.text.casefold() in policy.pii_allow
                or s.canonical.casefold() in policy.pii_allow
            ):
                continue
            counts[s.kind] += 1
            lab = label(s.kind)
            # block/anonymize: irreversible label (a secret never round-trips, not even to the user)
            tok = (
                self.vault.token(lab, s.canonical, s.text)
                if action == "pseudonymize"
                else lab
            )
            out += [text[last : s.start], f"[{tok}]"]
            last = s.end
        return "".join(out) + text[last:]

    def pseudonymize_many(
        self, texts: Iterable[str], policy: Policy
    ) -> Result[tuple[dict[str, str], Counter], str]:
        """text -> outgoing text. A text we produced by restoring is sent back exactly as the
        model first saw it (memo): Anthropic validates thinking signatures over that history."""
        texts = list(dict.fromkeys(texts))  # order kept: token numbers follow reading order
        with self.lock:
            out = {t: self.memo[t] for t in texts if t in self.memo}
        counts: Counter = Counter()
        match self.detect_many([t for t in texts if t not in out]):
            case Err(e):
                return Err(e)
            case Ok(spans):
                with self.lock:
                    out |= {
                        t: self.mask(t, sp, policy, counts) for t, sp in spans.items()
                    }
        return Ok((out, counts))

    def restore(self, text: str, escape: Callable[[str], str] = str) -> str:
        with self.lock:
            return restore(text, self.vault, escape)

    def remember(self, restored: str, sent: str) -> None:
        if restored != sent:
            with self.lock:
                self.memo[restored] = sent

    def save(self) -> None:
        """ponytail: whole-file rewrite, unbounded caches; prune by age if the file grows big."""
        if not self.path:
            return
        from src.guard.fsio import atomic_write

        with self.lock:
            data = json.dumps({
                "vault": self.vault.dump(),
                "spans": {h: [[s.start, s.end, s.kind, s.canonical] for s in v] for h, v in self.spans.items()},
                "memo": self.memo,
            }, ensure_ascii=False)  # fmt: skip
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(self.path, data)
        os.chmod(self.path, 0o600)
