"""Audit sink (ADR-0001 R2): run on the HOST; the sandboxed hook sends events to it (GUARD_AUDIT_SOCKET=host:port).

One JSON object per connection, answered "ok\\n" once it is chained into .guard/audit.jsonl. The agent can only
append through it: it cannot truncate or edit. It CAN send forged events (no shared secret) — they are chained and
timestamped like real ones, so history stays intact but is not proof of origin.
ponytail: no auth; reachable by any local process via the bound address. Upgrade: per-session HMAC secret.
"""

import argparse
import json
import socketserver
from datetime import UTC, datetime
from pathlib import Path

from src.guard import audit

MAX = 1 << 16


class Handler(socketserver.StreamRequestHandler):
    timeout = 5  # a stalled client must not pin a thread

    def handle(self) -> None:
        try:
            raw = self.rfile.readline(MAX + 1)
            event = json.loads(raw) if raw.endswith(b"\n") and len(raw) <= MAX else None
            if not isinstance(event, dict):
                raise ValueError("not a JSON object line")
            event.pop("ts", None)
            audit.record_local(self.server.root, event, datetime.now(UTC))  # type: ignore[attr-defined]
            self.wfile.write(b"ok\n")
        except (ValueError, OSError):
            self.wfile.write(b"err\n")


class Sink(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: tuple[str, int], root: Path) -> None:
        super().__init__(addr, Handler)
        self.root = root


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port-file", type=Path, required=True)
    a = ap.parse_args()
    with Sink((a.bind, 0), a.root) as s:
        a.port_file.write_text(str(s.server_address[1]))
        s.serve_forever()


if __name__ == "__main__":
    main()
