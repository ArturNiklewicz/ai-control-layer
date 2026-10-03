"""Append-only JSONL audit trail. Records decisions, rules, kinds and counts — never PII values."""

import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path


def record(root: Path, event: Mapping, now: datetime) -> None:
    d = root / ".guard"
    d.mkdir(exist_ok=True)
    if not (ignore := d / ".gitignore").exists():
        ignore.write_text("*\n")  # vault, grant and log never reach git
    with (d / "audit.jsonl").open("a") as f:
        f.write(json.dumps({"ts": now.isoformat(), **event}, ensure_ascii=False) + "\n")


def read(root: Path) -> list[dict]:
    p = root / ".guard" / "audit.jsonl"
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue  # a torn last line after a crash must not hide the rest
    return out
