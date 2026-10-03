"""Dependency direction, checked statically: apps -> shared modules, never app -> app."""

import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).parents[1] / "src"
SHARED = {"result", "llm"}
APP_OF = {"guard": "guard"}  # top-level name -> app
PURE = {
    "result.py",
    "guard/pii.py", "guard/commands.py", "guard/policy.py", "guard/anthropic.py",
    "guard/injection.py", "guard/report.py",
}  # fmt: skip  # stdlib only: importable/testable with nothing installed


def imports_of(source: str, package: tuple[str, ...]) -> set[str]:
    """Absolute module names, incl. `from src import x` (-> src.x) and relative imports."""
    out = set()
    for node in ast.walk(ast.parse(source)):
        if (  # importlib.import_module("src.x") / __import__("src.x")
            isinstance(node, ast.Call)
            and getattr(node.func, "attr", getattr(node.func, "id", ""))
            in ("import_module", "__import__")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            out.add(node.args[0].value)
        elif isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = list(package[: len(package) - node.level + 1]) if node.level else []
            mod = ".".join(base + ([node.module] if node.module else []))
            out |= {mod} | {f"{mod}.{a.name}" for a in node.names}
    return out


def owner(name: str) -> str:
    return "shared" if name in SHARED else APP_OF.get(name, name)


def src_owners(mods: set[str]) -> set[str]:
    return {owner(m.split(".")[1]) for m in mods if m.startswith("src.") and m.count(".") >= 1}


FILES = sorted(SRC.rglob("*.py"))


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(SRC)))
def test_dependency_direction(path):
    rel = path.relative_to(SRC)
    me = owner(rel.parts[0].removesuffix(".py"))
    mods = imports_of(path.read_text(), ("src", *rel.parts[:-1]))
    allowed = {"shared"} if me == "shared" else {"shared", me}
    assert src_owners(mods) <= allowed, f"{rel} imports {src_owners(mods) - allowed}"
    if rel.as_posix() in PURE:
        third = {m.split(".")[0] for m in mods} - set(sys.stdlib_module_names) - {"src"}
        assert not third, f"{rel} must stay stdlib-only, imports {third}"


def test_resolver_catches_indirect_forms():
    assert src_owners(imports_of("from src import guard", ("src", "result"))) == {"guard"}
    assert src_owners(imports_of("from ..guard import x", ("src", "x"))) == {"guard"}
    assert src_owners(imports_of("from . import pii", ("src", "guard"))) == {"guard"}
    assert src_owners(imports_of("import src.result", ("src", "guard"))) == {"shared"}
    dyn = 'import importlib\nimportlib.import_module("src.guard.cli")'
    assert src_owners(imports_of(dyn, ("src", "x"))) == {"guard"}
