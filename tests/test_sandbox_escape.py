"""Attack tests for the agent sandbox (ADR-0001 §10). Only meaningful inside the box:
src/guard/sandbox/run.sh selftest. Outside it they are skipped.

Each test is code an agent could write into tests/ and run via the allowed `pytest`:
the hook cannot see it, so the kernel must stop it.
"""

import os
import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(os.environ.get("GUARD_SANDBOX") != "1", reason="run inside the sandbox"),
]

REPO = Path("/repo")


def connect(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.mark.parametrize(
    "path", ["~/.ssh/id_rsa", "~/.config/sops/age/keys.txt", "~/.aws/credentials", "/Users", "/var/run/docker.sock"]
)
def test_host_secrets_do_not_exist(path):
    assert not Path(path).expanduser().exists()


def test_env_file_is_masked():
    for name in (".env", "secrets.env"):  # masked only when present on the host
        if (REPO / name).exists():
            assert (REPO / name).read_text() == ""
    assert shutil.which("sops") is None


@pytest.mark.parametrize(
    "path", [".git/hooks/pre-commit", ".git/config", "src/guard/policy.toml", "src/guard/new.py",
               ".hermes/plugins/ai-control-layer/plugin.yaml", ".hermes/plugins/ai-control-layer/__init__.py"]
)
def test_rules_and_git_are_read_only(path):
    with pytest.raises(OSError) as e:
        (REPO / path).write_text("pwned")
    assert e.value.errno == 30  # EROFS


@pytest.mark.parametrize("name", ["consent.sops.json", "vault.sops.json", "challenge.sops.json"])
def test_guard_state_is_read_only(name):  # agent must not forge consent or poison the vault
    with pytest.raises(OSError) as e:
        (REPO / ".guard" / name).write_text("forged")
    assert e.value.errno == 30  # EROFS


def test_agent_cannot_write_or_truncate_the_audit_log():  # R2: .guard is read-only, no rw mount of the log
    for flags in ("a", "w", "r+"):
        with pytest.raises(OSError) as e:
            (REPO / ".guard" / "audit.jsonl").open(flags)
        assert e.value.errno in (30, 2, 13)  # EROFS, or absent (the sink creates it on the host)
    assert not os.environ.get("GUARD_AUDIT_PATH")


def test_audit_reaches_the_host_sink_append_only():
    addr = os.environ.get("GUARD_SINK_PROBE") or os.environ.get("GUARD_AUDIT_SOCKET")
    assert addr, "run.sh sets it"
    host, port = addr.rsplit(":", 1)
    with socket.create_connection((host, int(port)), timeout=3) as s:
        s.sendall(b'{"event":"sandbox-probe"}\n')
        assert s.makefile("rb").readline() == b"ok\n"
    with socket.create_connection((host, int(port)), timeout=3) as s:
        s.sendall(b"not json\n")  # the sink has no verb for delete or overwrite: anything else is refused
        assert s.makefile("rb").readline() == b"err\n"


def test_repo_itself_is_writable():
    p = REPO / "tests" / ".sandbox_probe"
    p.write_text("ok")
    p.unlink()


@pytest.mark.parametrize("target", [("1.1.1.1", 443), ("8.8.8.8", 53), ("140.82.112.3", 443)])
def test_egress_is_blocked(target):
    assert not connect(*target)


def test_dns_is_blocked():
    with pytest.raises(OSError):
        socket.getaddrinfo("example.com", 443)


def test_ipv6_is_blocked():
    assert not connect("2606:4700:4700::1111", 443)


def test_model_api_egress_is_closed():
    # Hermes replaces Claude Code: no Anthropic egress exists any more — the only model door is
    # the guard gateway (127.0.0.1:8787) and its upstream (DGX). HOSTS stays empty by design.
    assert not connect("api.anthropic.com", 443)


@pytest.mark.skipif(os.environ.get("DGX_STATE") == "unreachable",
                    reason="DGX tailnet down on the host (run.sh probed it)")
def test_allowlisted_local_llm_is_reachable():
    assert connect("100.117.237.101", 8006)


def test_no_root_no_caps_no_sudo():
    assert os.getuid() != 0
    status = Path("/proc/self/status").read_text()
    caps = {line.split()[0]: int(line.split()[1], 16) for line in status.splitlines() if line.startswith("Cap")}
    assert caps["CapEff:"] == caps["CapPrm:"] == caps["CapBnd:"] == 0
    assert "NoNewPrivs:\t1" in status
    assert shutil.which("sudo") is None


def test_firewall_cannot_be_undone():
    r = subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], capture_output=True)
    assert r.returncode != 0


def test_root_filesystem_is_read_only():
    with pytest.raises(OSError):
        Path("/usr/local/bin/evil").write_text("x")


def test_fork_bomb_is_capped():
    procs = []
    try:
        with pytest.raises(OSError):
            for _ in range(2000):
                procs.append(subprocess.Popen(["sleep", "30"]))
        assert len(procs) < 512
    finally:
        for p in procs:
            p.kill()
            p.wait()
