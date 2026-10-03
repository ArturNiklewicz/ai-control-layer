"""Real MCP proxy process in front of a real (minimal) MCP stdio server."""

import json
import subprocess

import pytest

from tests.integration.conftest import PY, ROOT

pytestmark = [pytest.mark.integration, pytest.mark.mcp]

SERVER = r'''
import json, sys
docs = {"notatka": open(sys.argv[1]).read(), "readme": open(sys.argv[2]).read()}
for line in sys.stdin:
    m = json.loads(line)
    if m.get("method") == "tools/list":
        r = {"tools": [{"name": n} for n in ("find_symbol", "read_file", "delete_memory", "execute_shell_command")]}
    else:
        a = m["params"]["arguments"]
        r = {"content": [{"type": "text", "text": docs.get(a.get("doc"), a.get("echo", "ok"))}]}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
'''


def session(repo, calls):
    (repo.path / "server.py").write_text(SERVER)
    msgs = [{"jsonrpc": "2.0", "id": 0, "method": "tools/list"}] + [
        {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": a}}
        for i, (n, a) in enumerate(calls, 1)
    ]
    p = subprocess.run(
        [PY, "-m", "src.guard.mcp_proxy", "--server", "serena", "--",
         PY, str(repo.path / "server.py"), str(repo.path / "docs/mops_notatka.txt"), str(repo.path / "docs/readme_z_injection.md")],
        input="".join(json.dumps(m) + "\n" for m in msgs), capture_output=True, text=True, cwd=ROOT, env=repo.env, timeout=60,
    )  # fmt: skip
    return {m["id"]: m["result"] for m in map(json.loads, p.stdout.splitlines())}


def text(result):
    return result["content"][0]["text"]


CASES = [
    ("dozwolone narzędzie, czysty wynik", ("find_symbol", {"echo": "def main(): ..."}), "def main(): ...", [pytest.mark.positive]),
    ("narzędzie spoza allowlisty", ("delete_memory", {}), "mcp-not-allowlisted", [pytest.mark.negative]),
    ("wykonanie komend przez MCP", ("execute_shell_command", {"command": "id"}), "mcp-not-allowlisted", [pytest.mark.negative]),
    ("ścieżka poza repo w argumencie", ("read_file", {"relative_path": "../../../etc/passwd"}), "path-escape", [pytest.mark.negative]),
    ("sekret w argumencie (wyciek do serwera)", ("find_symbol", {"echo": "AKIAIOSFODNN7EXAMPLE"}), "pii-args", [pytest.mark.negative, pytest.mark.pii]),
    ("wynik z ukrytym injection", ("read_file", {"doc": "readme"}), "injection", [pytest.mark.negative, pytest.mark.injection]),
    ("wynik z PII bez zgody", ("read_file", {"doc": "notatka"}), "no-consent", [pytest.mark.negative, pytest.mark.pii]),
]  # fmt: skip


@pytest.mark.parametrize("scenario, call, expect", [pytest.param(s, c, e, marks=m, id=s) for s, c, e, m in CASES])
def test_mcp_call(repo, say, scenario, call, expect):
    say.title(f"MCP: {scenario}")
    say.step(f"tools/call {call[0]} {call[1]}")
    res = session(repo, [call])
    out = text(res[1])
    (say.blocked if "[guard:" in out else say.ok)(out[:300])
    assert expect in out
    assert "47030502913" not in out


def test_tools_list_is_filtered(repo, say):
    say.title("MCP: agent widzi tylko narzędzia z allowlisty")
    tools = [t["name"] for t in session(repo, [])[0]["tools"]]
    say.ok(f"serwer ma 4 narzędzia, agent widzi: {tools}")
    assert tools == ["find_symbol", "read_file"]


@pytest.mark.consent
@pytest.mark.pii
@pytest.mark.positive
def test_pii_output_anonymized_after_login(repo, say, age_key):
    say.title("MCP: po zalogowaniu i zgodzie wynik z PII jest anonimizowany, nie wstrzymany")
    assert repo.login("t")[0] == 0
    say.ok("login + zgoda")
    out = text(session(repo, [("read_file", {"doc": "notatka"})])[1])
    say.show("wynik dla agenta", out)
    assert "[PESEL]" in out and "47030502913" not in out and "t.zielinski@example.com" not in out
