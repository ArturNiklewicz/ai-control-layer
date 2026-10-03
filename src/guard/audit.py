"""Append-only JSONL audit trail. Records decisions, rules, kinds and counts — never PII values.

GUARD_AUDIT_PATH redirects the log (the sandbox mounts only that file writable; `.guard/` is read-only there).
"""

import json
import os
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path


def path_of(root: Path) -> Path:
    return Path(os.environ.get("GUARD_AUDIT_PATH") or root / ".guard" / "audit.jsonl")


def record(root: Path, event: Mapping, now: datetime) -> None:
    p = path_of(root)
    if not os.environ.get("GUARD_AUDIT_PATH"):
        d = root / ".guard"
        if d.is_symlink():
            raise OSError(f"{d}: refusing symlinked .guard")
        d.mkdir(exist_ok=True)
        if not os.path.lexists(ignore := d / ".gitignore"):
            ignore.write_text("*\n")  # vault, grant and log never reach git
    fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)  # ELOOP on a symlink
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps({"ts": now.isoformat(), **event}, ensure_ascii=False) + "\n")


def read(root: Path) -> list[dict]:
    p = path_of(root)
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue  # a torn last line after a crash must not hide the rest
    return out
