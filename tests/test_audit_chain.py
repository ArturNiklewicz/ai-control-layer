"""Audit hash chain (tamper-evidence) and the host-side sink (tamper-resistance)."""

import json
import socket
import threading
from datetime import UTC, datetime
from multiprocessing import Pool

import pytest

from src.guard import audit, audit_sink

NOW = datetime(2026, 1, 1, tzinfo=UTC)

pytestmark = pytest.mark.audit


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("GUARD_AUDIT_PATH", raising=False)
    monkeypatch.delenv("GUARD_AUDIT_SOCKET", raising=False)


def fill(root, n=5):
    for i in range(n):
        audit.record(root, {"event": "e", "i": i}, NOW)
    return root / ".guard" / "audit.jsonl"


def test_intact_chain_verifies_and_empty_is_ok(tmp_path):
    assert audit.verify(tmp_path) == (True, None)
    assert audit.verify(fill(tmp_path).parents[1]) == (True, None)
    assert [e["i"] for e in audit.read(tmp_path)] == list(range(5))


def test_first_record_chains_to_genesis(tmp_path):
    fill(tmp_path, 1)
    assert audit.read(tmp_path)[0]["prev"] == "0" * 64


def test_edit_is_detected(tmp_path):
    p = fill(tmp_path)
    lines = p.read_text().splitlines()
    lines[2] = lines[2].replace('"i": 2', '"i": 9')
    p.write_text("\n".join(lines) + "\n")
    assert audit.verify(tmp_path) == (False, 3)  # the line AFTER the edit no longer matches


def test_truncation_in_the_middle_is_detected(tmp_path):
    p = fill(tmp_path)
    lines = p.read_text().splitlines()
    p.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert audit.verify(tmp_path) == (False, 1)


def test_reorder_is_detected(tmp_path):
    p = fill(tmp_path)
    lines = p.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert audit.verify(tmp_path)[0] is False


def test_deleting_the_head_is_detected(tmp_path):
    p = fill(tmp_path)
    p.write_text("\n".join(p.read_text().splitlines()[1:]) + "\n")
    assert audit.verify(tmp_path) == (False, 0)


def test_legacy_lines_without_prev_are_skipped(tmp_path):
    (tmp_path / ".guard").mkdir()
    (tmp_path / ".guard" / "audit.jsonl").write_text('{"event":"old"}\n{"event":"older"}\n')
    audit.record(tmp_path, {"event": "new"}, NOW)
    audit.record(tmp_path, {"event": "newer"}, NOW)
    assert audit.verify(tmp_path) == (True, None)
    assert audit.read(tmp_path)[2]["prev"] != "0" * 64  # chained onto the legacy line, which stays unprotected


def test_torn_last_line_does_not_break_later_appends(tmp_path):
    p = fill(tmp_path, 2)
    p.write_text(p.read_text() + '{"event":"torn"')  # crash mid-write
    audit.record(tmp_path, {"event": "after"}, NOW)
    assert audit.read(tmp_path)[-1]["event"] == "after"
    assert audit.verify(tmp_path) == (False, 2)  # the torn line itself is reported; later lines chain onto it


def _append(args):
    root, i = args
    audit.record(root, {"event": "p", "i": i}, NOW)


def test_concurrent_processes_keep_a_valid_chain(tmp_path):
    with Pool(8) as pool:
        pool.map(_append, [(tmp_path, i) for i in range(80)])
    assert len(audit.read(tmp_path)) == 80
    assert audit.verify(tmp_path) == (True, None)


def test_concurrent_threads_keep_a_valid_chain(tmp_path):
    ts = [threading.Thread(target=_append, args=((tmp_path, i),)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(audit.read(tmp_path)) == 40
    assert audit.verify(tmp_path) == (True, None)


def test_sink_chains_events_and_refuses_garbage(tmp_path):
    with audit_sink.Sink(("127.0.0.1", 0), tmp_path) as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]

        def send(raw: bytes) -> bytes:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as s:
                s.sendall(raw)
                return s.makefile("rb").readline()

        assert send(b'{"event":"a","ts":"forged"}\n') == b"ok\n"
        assert send(b"[1]\n") == b"err\n"
        assert send(b"not json\n") == b"err\n"
        assert send(b"x" * (audit_sink.MAX + 10) + b"\n") == b"err\n"
        assert send(b'{"event":"b"}\n') == b"ok\n"
        srv.shutdown()
    got = audit.read(tmp_path)
    assert [e["event"] for e in got] == ["a", "b"] and got[0]["ts"] != "forged"
    assert audit.verify(tmp_path) == (True, None)


def test_record_goes_through_the_socket_when_set(tmp_path, monkeypatch):
    (tmp_path / "host").mkdir()
    with audit_sink.Sink(("127.0.0.1", 0), tmp_path / "host") as srv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        monkeypatch.setenv("GUARD_AUDIT_SOCKET", f"127.0.0.1:{srv.server_address[1]}")
        audit.record(tmp_path / "agent-view", {"event": "viaSink"}, NOW)
        srv.shutdown()
    assert not (tmp_path / "agent-view").exists()  # nothing written locally
    assert audit.read(tmp_path / "host")[0]["event"] == "viaSink"


def test_unreachable_sink_raises_not_silently_drops(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARD_AUDIT_SOCKET", "127.0.0.1:1")
    with pytest.raises(OSError):
        audit.record(tmp_path, {"event": "x"}, NOW)


def test_lines_are_valid_json(tmp_path):
    for line in fill(tmp_path).read_text().splitlines():
        assert set(json.loads(line)) >= {"ts", "prev", "event"}
