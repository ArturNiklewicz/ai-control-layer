"""Shared fixtures for guard tests: the shipped policy, adjustable per test."""

import copy
import tomllib
from pathlib import Path

from src.guard.policy import Policy, parse

ROOT = Path(__file__).parents[1]
RAW = tomllib.loads((ROOT / "src/guard/policy.toml").read_text())


def policy(**overrides) -> Policy:
    raw = copy.deepcopy(RAW)
    for dotted, value in overrides.items():
        *path, key = dotted.split("__")
        node = raw
        for p in path:
            node = node.setdefault(p, {})
        node[key] = value
    return parse(raw).value  # type: ignore[union-attr]
