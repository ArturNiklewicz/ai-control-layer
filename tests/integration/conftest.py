"""Integration fixtures: narrated steps, a throwaway guarded repo, real CLI / hook / proxy runs."""

import json
import os
import pty
import select
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
CORPUS = Path(__file__).parent / "corpus"
PY = sys.executable
DGX = ("100.117.237.101", 8006)
DOCKER_BIN = "/Applications/Docker.app/Contents/Resources/bin"


# --- narration: visible with `pytest -s`, silent (captured) otherwise ---


class Narrator:
    def title(self, text: str) -> None:
        print(f"\n\n━━ {text}", flush=True)

    def step(self, text: str) -> None:
        print(f"  ▶ {text}", flush=True)

    def ok(self, text: str) -> None:
        print(f"    ✓ {text}", flush=True)

    def blocked(self, text: str) -> None:
        print(f"    ⛔ {text}", flush=True)

    def show(self, label: str, text: str, limit: int = 900) -> None:
        body = text if len(text) <= limit else text[:limit] + " …"
        print(f"    ┌ {label}", flush=True)
        for line in body.rstrip().splitlines():
            print(f"    │ {line}", flush=True)
        print("    └", flush=True)


@pytest.fixture
def say() -> Narrator:
    return Narrator()


# --- resources: skip cleanly when absent ---


def reachable(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
        return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def dgx():
    if not reachable(*DGX):
        pytest.skip(f"local LLM {DGX[0]}:{DGX[1]} unreachable")


@pytest.fixture(scope="session")
def docker_env():
    env = os.environ | {"PATH": os.environ["PATH"] + os.pathsep + DOCKER_BIN}
    if subprocess.run(["docker", "info"], capture_output=True, env=env).returncode != 0:
        pytest.skip("Docker is not running")
    return env


@pytest.fixture(scope="session")
def age_key():
    if not shutil.which("sops") or not (Path.home() / ".config/sops/age/keys.txt").exists():
        pytest.skip("sops or age key absent")


# --- a throwaway project guarded by the real policy ---


@dataclass
class Repo:
    path: Path
    env: dict

    @property
    def policy(self) -> Path:
        return self.path / "policy.toml"

    def edit_policy(self, old: str, new: str) -> None:
        text = self.policy.read_text()
        assert old in text, old
        self.policy.write_text(text.replace(old, new))

    def audit(self) -> list[dict]:
        p = self.path / ".guard/audit.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def cli(self, *args: str, timeout: float = 180) -> subprocess.CompletedProcess:
        p = subprocess.run([PY, "-m", "src.guard.cli", *args], capture_output=True, text=True,
                           cwd=ROOT, env=self.env, timeout=timeout)  # fmt: skip
        p.stdout, p.stderr = (x.replace(str(self.path), "<repo>") for x in (p.stdout, p.stderr))
        return p

    def hook(self, payload: dict, agent: str | None = None) -> dict | None:
        payload = {"hook_event_name": "PreToolUse", "cwd": str(self.path)} | payload
        env = self.env | ({"GUARD_AGENT": agent} if agent else {})
        p = subprocess.run([PY, "-m", "src.guard.hook"], input=json.dumps(payload), capture_output=True,
                           text=True, cwd=ROOT, env=env, timeout=30)  # fmt: skip
        assert p.returncode == 0, p.stderr
        return json.loads(p.stdout) if p.stdout.strip() else None

    def login(self, answer: str = "t") -> tuple[int, str]:
        """Drive `guard login` through a real pseudo-terminal, like a human at a keyboard."""
        master, slave = pty.openpty()
        p = subprocess.Popen([PY, "-m", "src.guard.cli", "login"], stdin=slave, stdout=slave, stderr=slave,
                             cwd=ROOT, env=self.env, close_fds=True)  # fmt: skip
        os.close(slave)
        out, answered, deadline = b"", False, time.time() + 60
        while time.time() < deadline:
            if not answered and b"[t/N]" in out:
                os.write(master, f"{answer}\n".encode())
                answered = True
            r, _, _ = select.select([master], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:  # EIO: child closed the terminal
                    break
                if not chunk:
                    break
                out += chunk
            elif p.poll() is not None:
                break
        p.wait(timeout=30)
        os.close(master)
        return p.returncode, out.decode(errors="replace").replace("\r", "")


def make_repo(tmp: Path, semantic: bool) -> Repo:
    (tmp / "src").mkdir()
    (tmp / "src/app.py").write_text("def main():\n    return 'ok'\n")
    (tmp / ".env").write_text("OPENAI_API_KEY=sk-should-never-leak-0000000000000000\n")
    (tmp / "docs").mkdir()
    for f in CORPUS.iterdir():
        shutil.copy(f, tmp / "docs" / f.name)
    pol = (ROOT / "src/guard/policy.toml").read_text()
    pol = pol.replace('"src/guard/signatures.json"', json.dumps(str(ROOT / "src/guard/signatures.json")))
    if not semantic:
        pol = pol.replace("semantic = true", "semantic = false")
    (tmp / "policy.toml").write_text(pol)
    env = os.environ | {"CLAUDE_PROJECT_DIR": str(tmp), "GUARD_POLICY": str(tmp / "policy.toml")}
    env.pop("GUARD_AGENT", None)
    return Repo(tmp, env)


@pytest.fixture
def repo(tmp_path) -> Repo:
    """Regex-only PII detection: deterministic, no model needed."""
    return make_repo(tmp_path.resolve(), semantic=False)


@pytest.fixture
def live_repo(tmp_path, dgx) -> Repo:
    """Full hybrid detection: regex + local LLM NER on DGX."""
    return make_repo(tmp_path.resolve(), semantic=True)


def verdict(out: dict | None) -> str:
    if out is None:
        return "allow"
    return out.get("hookSpecificOutput", {}).get("permissionDecision") or out.get("decision", "?")


def reason(out: dict | None) -> str:
    if out is None:
        return ""
    return out.get("hookSpecificOutput", {}).get("permissionDecisionReason") or out.get("reason", "")
