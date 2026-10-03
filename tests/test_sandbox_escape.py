"""Attack tests for the agent sandbox (ADR-0001 §10). Only meaningful inside the box:
src/guard/sandbox/run.sh selftest. Outside it they are skipped.

Each test is code an agent could write into tests/ and run via the allowed `pytest`:
the hook cannot see it, so the kernel must stop it.
"""

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
    assert (REPO / ".env").read_text() == ""
    assert (REPO / "secrets.env").exists()  # committed file, encrypted; no age key to open it
    assert shutil.which("sops") is None


@pytest.mark.parametrize(
    "path", [".git/hooks/pre-commit", ".git/config", "src/guard/policy.toml", "src/guard/new.py", ".claude/settings.json"]
)
def test_rules_and_git_are_read_only(path):
    with pytest.raises(OSError) as e:
        (REPO / path).write_text("pwned")
    assert e.value.errno == 30  # EROFS


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


def test_allowlisted_model_api_is_reachable():
    assert connect("api.anthropic.com", 443)


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
