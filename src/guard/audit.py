"""Append-only JSONL audit trail. Records decisions, rules, kinds and counts — never PII values.

Tamper-evidence: every line carries "prev" = sha256 of the previous line's raw bytes ("0"*64 for the first), so
editing, reordering or deleting a line in the middle breaks `verify`. Lines written before the chain existed have no
"prev"; the chain is checked from the first line that has one. NOT detected: truncating the tail (or the whole file)
without a trailing anchor — ponytail: publish the head hash out-of-band (host-signed) to close that.

Tamper-resistance: GUARD_AUDIT_SOCKET=host:port sends events to `audit_sink`, which runs outside the agent's box
and is the only writer of the file (the sandbox mounts `.guard/` read-only). GUARD_AUDIT_PATH redirects the log.
"""

import fcntl  # ponytail: POSIX-only flock; ceiling = one host, local fs. Upgrade: sink is the single writer.
import hashlib
import json
import os
import socket
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

GENESIS = "0" * 64
TAIL = 1 << 20  # longest line we can chain onto; longer = refuse rather than hash a fragment


def path_of(root: Path) -> Path:
    return Path(os.environ.get("GUARD_AUDIT_PATH") or root / ".guard" / "audit.jsonl")


def _prev_and_torn(fd: int) -> tuple[str, bool]:
    size = os.fstat(fd).st_size
    n = min(size, TAIL)
    parts = os.pread(fd, n, size - n).split(b"\n")
    torn = parts[-1] != b""  # crash mid-write: no trailing newline
    i = len(parts) - 1 if torn else len(parts) - 2
    if size > n and i == 0:
        raise OSError("audit: last line too long to chain")
    return (hashlib.sha256(parts[i]).hexdigest() if i >= 0 else GENESIS), torn


def record_local(root: Path, event: Mapping, now: datetime) -> None:
    p = path_of(root)
    if not os.environ.get("GUARD_AUDIT_PATH"):
        d = root / ".guard"
        if d.is_symlink():
            raise OSError(f"{d}: refusing symlinked .guard")
        d.mkdir(exist_ok=True)
        if not os.path.lexists(ignore := d / ".gitignore"):
            ignore.write_text("*\n")  # vault, grant and log never reach git
    rec = {"ts": now.isoformat(), **event}
    fd = os.open(p, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)  # ELOOP on a symlink
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # read-last-line + append must be atomic across hook processes
        prev, torn = _prev_and_torn(fd)
        line = json.dumps(rec | {"prev": prev}, ensure_ascii=False).encode()
        if os.write(fd, (b"\n" if torn else b"") + line + b"\n") != len(line) + 1 + torn:
            raise OSError("audit: short write")
    finally:
        os.close(fd)  # also releases the lock


def record(root: Path, event: Mapping, now: datetime) -> None:
    if addr := os.environ.get("GUARD_AUDIT_SOCKET"):
        host, _, port = addr.rpartition(":")
        with socket.create_connection((host, int(port)), timeout=3) as s:
            s.sendall(json.dumps(dict(event)).encode() + b"\n")  # ts and prev are the sink's to set
            if s.makefile("rb").readline() != b"ok\n":
                raise OSError("audit sink refused the event")
        return
    record_local(root, event, now)


def verify(root: Path) -> tuple[bool, int | None]:
    """(ok, index of the first broken line). Chain starts at the first line carrying "prev"."""
    p = path_of(root)
    lines = p.read_bytes().split(b"\n") if p.exists() else []
    if lines and lines[-1] == b"":
        lines.pop()
    started = False
    for i, raw in enumerate(lines):
        try:
            prev = json.loads(raw).get("prev")
        except (ValueError, AttributeError):
            prev = None
        if not started and prev is None:
            continue  # pre-chain line
        started = True
        if prev != (hashlib.sha256(lines[i - 1]).hexdigest() if i else GENESIS):
            return False, i
    return True, None


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
