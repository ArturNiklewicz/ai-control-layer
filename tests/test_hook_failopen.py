"""Regression: every reproduced fail-open path in the hook must deny."""

import json
import time

import pytest

from src.guard.pii import detect
from tests.test_guard_e2e import hook, repo, verdict  # noqa: F401

PII = "aws_key AKIA" + "IOSFODNN7EXAMPLE\n"  # a `block` kind: reads of it deny
KEY = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"


def read(repo, name):
    return {"tool_name": "Read", "tool_input": {"file_path": str(repo / name)}}


def test_redos_private_key_marker_is_linear():
    t = time.perf_counter()
    assert not detect("-----BEGIN PRIVATE KEY-----" * 75000)
    assert time.perf_counter() - t < 3  # quadratic took minutes; slack for loaded CI
    assert any(s.kind == "SECRET" for s in detect(KEY))


def test_time_budget_fails_closed(repo):
    import os
    import subprocess
    import sys

    from tests.guard_fixtures import ROOT

    r = subprocess.run(
        [sys.executable, "-c", "import sys,time,src.guard.hook as h;h.json.load=lambda f:time.sleep(30);sys.exit(h.main())"],
        input="{}", capture_output=True, text=True, cwd=ROOT, timeout=20,
        env=os.environ | {"CLAUDE_PROJECT_DIR": str(repo), "GUARD_POLICY": str(repo / "policy.toml"), "GUARD_HOOK_BUDGET_S": "1"},
    )  # fmt: skip
    assert (
        r.returncode == 0
        and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    )
    assert "timeout" in r.stdout


def test_oversize_and_undecodable_reads_denied(repo):
    (repo / "huge.txt").write_text(PII + "x" * 2_100_000)
    assert verdict(hook(repo, read(repo, "huge.txt"))) == "deny"
    (repo / "tail.txt").write_text("x" * 2_100_000 + PII)
    assert verdict(hook(repo, read(repo, "tail.txt"))) == "deny"
    (repo / "cp.txt").write_bytes(b"\xb3\xf3d\xbc " + PII.encode())
    assert verdict(hook(repo, read(repo, "cp.txt"))) == "deny"


@pytest.mark.parametrize(
    "call",
    [
        {
            "tool_name": "Grep",
            "tool_input": {
                "pattern": ".",
                "path": "keys.txt",
                "output_mode": "content",
            },
        },
        {"tool_name": "Grep", "tool_input": {"pattern": ".", "output_mode": "content"}},
        {
            "tool_name": "Grep",
            "tool_input": {"pattern": ".", "path": ".", "output_mode": "content"},
        },
        {"tool_name": "NotebookRead", "tool_input": {"notebook_path": "keys.txt"}},
        {"tool_name": "Bash", "tool_input": {"command": "cat k*.txt"}},
        {"tool_name": "Bash", "tool_input": {"command": "cd src && cat ../keys.txt"}},
    ],
)
def test_other_read_paths_scanned(repo, call):
    assert verdict(hook(repo, call)) == "deny"


def test_bash_cd_target_resolved(repo):
    (repo / "sub").mkdir()
    (repo / "sub/n.txt").write_text(PII)
    assert (
        verdict(
            hook(
                repo,
                {"tool_name": "Bash", "tool_input": {"command": "cd sub && cat n.txt"}},
            )
        )
        == "deny"
    )
    assert (
        verdict(
            hook(
                repo, {"tool_name": "Bash", "tool_input": {"command": "cat sub/*.txt"}}
            )
        )
        == "deny"
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"tool_name": "Read", "tool_input": None},
        {"tool_name": "Read", "tool_input": []},
        {"tool_name": "Read", "tool_input": {}},
        {"tool_name": "Read", "tool_input": {"file_path": 5}},
        {"tool_name": "Bash", "tool_input": {"command": ["cat"]}},
        {"tool_input": {}},
        {"tool_name": 7, "tool_input": {}},
        {"hook_event_name": "UserPromptSubmit"},
        {"hook_event_name": "userpromptsubmit", "prompt": "44051401359"},
        {"hook_event_name": "Nope", "tool_name": "Read", "tool_input": {}},
    ],
)
def test_malformed_denies(repo, payload):
    assert verdict(hook(repo, payload)) in ("deny", "block")


def test_lone_surrogate_denies(repo):
    out = hook(repo, {"tool_name": "mcp__\ud800x", "tool_input": {}})
    assert verdict(out) == "deny"


def test_multiedit_new_string_scanned(repo):
    call = {
        "tool_name": "MultiEdit",
        "tool_input": {
            "file_path": "src/ok.py",
            "edits": [{"old_string": "a", "new_string": KEY}],
        },
    }
    assert verdict(hook(repo, call)) == "deny"
