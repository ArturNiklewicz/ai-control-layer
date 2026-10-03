"""Dashboard: embedded data round-trips, no script breakout, empty log renders, CLI writes 0600 file."""

import json
import re
from pathlib import Path
from datetime import UTC, datetime

from src.guard import cli
from src.guard.report import pct, render_html

NOW = datetime(2026, 10, 3, 20, 0, tzinfo=UTC)
EVENTS = [
    {"ts": "2026-10-03T18:00:00+00:00", "event": "PreToolUse", "agent": "default", "tool": "Write", "verdict": "deny", "rule": "pii-write", "pii": {"SECRET": 1}, "latency_ms": 100.0},
    {"ts": "2026-10-03T18:01:00+00:00", "event": "UserPromptSubmit", "agent": "default", "verdict": "allow", "rule": "ok", "latency_ms": 10.0},
    {"ts": "2026-10-03T18:02:00+00:00", "event": "gateway", "principal": "demo", "model": "m", "upstream": "private", "verdict": "allow", "rule": "ok", "tokens": 18, "cost_usd": 0.5, "guard_ms": 8.0, "latency_ms": 300.0, "judge_score": 0.95},
    {"ts": "2026-10-03T18:03:00+00:00", "event": "gateway", "principal": "demo", "model": "x", "verdict": "deny", "rule": "model-denied", "signatures": ["inj-1"]},
    {"ts": "2026-10-03T18:04:00+00:00", "event": "gateway", "api": "anthropic", "verdict": "allow", "rule": "ok", "pii": {"PERSON": 2}},
]  # fmt: skip


def data_of(html: str) -> dict:
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S)
    assert m
    return json.loads(m.group(1))


def test_counts_round_trip():
    d = data_of(render_html(EVENTS, NOW))
    assert d["kpi"]["events"] == 5
    assert d["kpi"]["decisions"] == 5  # the proxied request is a decision too
    assert d["kpi"]["denies"] == 2
    assert d["kpi"]["block_rate"] == 0.4
    assert d["kpi"]["spend_total"] == d["kpi"]["spend_today"] == 0.5
    assert d["kpi"]["tokens"] == 18
    assert d["posture"]["proxied"] == 1
    assert d["signatures"] == [["inj-1", 1]]
    assert len(d["rows"]) == 5


def test_script_breakout_impossible():
    evil = "</script><script>alert(1)</script><!--"
    html = render_html([{**EVENTS[0], "rule": evil, "tool": evil}], NOW)
    assert html.count("</script>") == 2  # data + code, nothing injected
    assert "<!--" not in html.split('id="data">')[1].split("</script>")[0]
    assert evil in json.dumps(data_of(html))


def test_empty_renders():
    d = data_of(render_html([], NOW))
    assert d["kpi"]["events"] == 0
    assert d["kpi"]["block_rate"] == 0
    assert d["rows"] == []


def test_percentiles():
    xs = [float(i) for i in range(1, 101)]
    assert pct(xs, 0.5) in (50.0, 51.0)
    assert pct(xs, 0.95) in (95.0, 96.0)
    assert pct([7.0], 0.95) == 7.0


def test_cli_writes_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setenv("GUARD_POLICY", str(Path(__file__).parents[1] / "src/guard/policy.toml"))
    monkeypatch.setenv("GUARD_AUDIT_PATH", str(tmp_path / "a.jsonl"))
    (tmp_path / "a.jsonl").write_text(json.dumps(EVENTS[0]) + "\n")
    out = tmp_path / "out" / "d.html"
    assert cli.main(["dashboard", "-o", str(out)]) == 0
    assert data_of(out.read_text())["kpi"]["denies"] == 1
    assert out.stat().st_mode & 0o777 == 0o600
