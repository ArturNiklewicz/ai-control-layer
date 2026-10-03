"""Access decisions for agent actions: Bash commands, file paths, tools, MCP calls.

Default deny. A command passes only if every segment matches an allowed prefix and every
path it touches resolves (symlinks included) inside the repo and outside protected globs.
The guard only restricts: "allow" means "no objection", the normal permission flow still runs.

ponytail: a whitelist cannot contain code execution: an allowed test runner runs code the
agent can write. Real containment = OS sandbox (container / Claude Code sandbox); this layer
is the auditable policy on top of it.
"""

import fnmatch
import glob
import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from src.guard.policy import Agent, Policy

type Verdict = Literal["allow", "ask", "deny"]


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    rule: str  # stable id for audit/dashboard: path-escape, not-allowlisted, ...
    reason: str


ALLOW = Decision("allow", "ok", "")
SEPARATORS = {";", "&&", "||", "|", "&"}
REDIRECTS = {">", ">>", "<", ">&", "&>", "<>", ">|"}
# shell features that hide what will run; checked on the raw string, before tokenizing
FORBIDDEN = {
    "$": "expansion",
    "`": "command substitution",
    "\n": "multi-line",
    "<<": "heredoc",
}


def deny(rule: str, reason: str) -> Decision:
    return Decision("deny", rule, reason)


def check_path(raw: str, cwd: Path, root: Path, policy: Policy) -> Decision:
    target = Path(os.path.expanduser(raw))
    target = target if target.is_absolute() else cwd / target
    candidates = glob.glob(str(target)) if glob.has_magic(raw) else []
    for p in [target, *map(Path, candidates)]:
        real = Path(
            os.path.realpath(p)
        )  # follows symlinks: a link out of the repo is an escape
        if not real.is_relative_to(root):
            return deny("path-escape", f"{raw!r} resolves outside the repo ({real})")
        rel = real.relative_to(root).as_posix()
        hit = next((g for g in policy.deny_paths if protected(rel, g)), None)
        if hit:
            return deny("protected-path", f"{rel!r} is protected by paths.deny {hit!r}")
    return ALLOW


def protected(rel: str, pattern: str) -> bool:
    rel, pattern = rel.casefold(), pattern.casefold()  # APFS/NTFS: `.ENV` is `.env`
    if pattern.endswith("/**"):  # a directory and everything under it
        base = pattern[:-3]
        return (
            rel == base
            or rel.startswith(base + "/")
            or fnmatch.fnmatchcase(rel, pattern)
        )
    return fnmatch.fnmatchcase(rel, pattern) or fnmatch.fnmatchcase(
        Path(rel).name, pattern
    )


def is_denied(tok: str, deny: frozenset[str]) -> bool:
    """`--opt`, `--opt=v`, abbreviated `--op` (argparse/getopt), `-X` inside a cluster or glued."""
    if tok.startswith("--"):
        name = tok.split("=", 1)[0]
        return name in deny or (
            len(name) > 2 and any(d.startswith(name) for d in deny if d[:2] == "--")
        )
    if tok.startswith("-") and len(tok) > 1:
        return any(
            tok.startswith(d) if len(d) > 2 else d[1] in tok[1:]
            for d in deny
            if d[:2] != "--"
        )
    return False


def exposes(raw: str, cwd: Path, root: Path, policy: Policy) -> str | None:
    """A directory arg whose subtree holds a protected path: recursive tools would read it.

    ponytail: walks the real tree (stops at the first hit); upgrade = a prebuilt index.
    """
    target = Path(os.path.expanduser(raw))
    target = target if target.is_absolute() else cwd / target
    for p in glob.glob(str(target)) if glob.has_magic(raw) else [target]:
        real = Path(os.path.realpath(p))
        if not (real.is_dir() and real.is_relative_to(root)):
            continue
        for dirpath, dirs, files in os.walk(real):
            for n in dirs + files:
                rel = (Path(dirpath) / n).relative_to(root).as_posix()
                if any(protected(rel, g) for g in policy.deny_paths):
                    return rel
    return None


def tokenize(cmd: str) -> list[str] | None:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes
        return None


def segments(tokens: list[str]) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for t in tokens:
        if t in SEPARATORS:
            out.append([])
        else:
            out[-1].append(t)
    return [s for s in out if s]


def matches(tokens: list[str], prefixes: tuple[tuple[str, ...], ...]) -> bool:
    return any(tuple(tokens[: len(p)]) == p for p in prefixes)


# extra per-command denials, keyed by the command (`uv run pytest` -> pytest)
CMD_DENY = {
    "pytest": frozenset({
        "-p", "-c", "-o", "--pyargs", "--rootdir", "--confcutdir", "--junitxml",
        "--junit-xml", "--basetemp", "--pdb", "--log-file",
    }),
    "tail": frozenset({"-F", "--follow"}),
}  # fmt: skip
BRANCH_OK = {"--list", "-l", "--show-current", "-a", "--all", "-r", "--remotes", "-v", "-vv"}
ADD_ALL = frozenset({"-A", "--all", "-u", "--update"})


def command_name(words: list[str]) -> str:
    if words[0] == "uv" and "pytest" in words[:4]:
        return "pytest"
    return words[0]


def decide_bash(
    cmd: str, cwd: Path, root: Path, policy: Policy, agent: Agent
) -> Decision:
    for needle, what in FORBIDDEN.items():
        if needle in cmd:
            return deny("shell-feature", f"{what} ({needle!r}) is not allowed")
    tokens = tokenize(cmd)
    if tokens is None:
        return deny("parse", "unbalanced quotes")
    if {"(", ")"} & set(tokens):
        return deny("shell-feature", "subshells are not allowed")
    if any("{" in t and t != "{}" for t in tokens):  # brace expansion hides paths
        return deny("shell-feature", "brace expansion is not allowed")
    asks = []
    for seg in segments(tokens):
        if "=" in seg[0] and seg[0].split("=")[0].isidentifier():
            return deny(
                "env-assignment", f"{seg[0]!r}: env overrides can redirect tools"
            )
        words, paths, i = [], [], 0
        while i < len(seg):  # split out redirect targets: they are paths, not arguments
            if seg[i] in REDIRECTS:
                if i + 1 >= len(seg):
                    return deny("parse", "redirect without target")
                if not (seg[i + 1] == "/dev/null" or seg[i + 1].isdigit()):
                    paths.append(seg[i + 1])
                i += 2
            else:
                words.append(seg[i])
                i += 1
        if not words:
            return deny("parse", "empty command")
        name = command_name(words)
        deny_set = policy.deny_tokens | CMD_DENY.get(name, frozenset())
        if bad := next((t for t in words if is_denied(t, deny_set)), None):
            return deny("denied-token", f"{bad!r} is in commands.deny_tokens")
        args = [w for w in words[1:] if not w.startswith("-")]
        if words[:2] == ["git", "branch"] and (
            any(w.startswith("-") and w not in BRANCH_OK for w in words[2:])
            or (args[1:] and not {"--list", "-l"} & set(words))
        ):
            return deny("git-branch", "git branch only lists (--list/--show-current)")
        if words[:2] == ["git", "add"] and any(
            is_denied(w, ADD_ALL) for w in words[2:]
        ):
            return deny("git-add-all", "stage explicit files, not -A/-u")
        if matches(words, agent.ask):
            asks.append(" ".join(words[:2]))
        elif not matches(words, agent.commands):
            return deny(
                "not-allowlisted",
                f"{' '.join(words[:3])!r} is not in the command whitelist",
            )
        for w in words[1:]:
            value = w.split("=", 1)[1] if w.startswith("-") and "=" in w else w
            if not value.startswith("-"):
                paths.append(value)
        if words[0] == "cd" and len(words) == 1:
            return deny("path-escape", "bare `cd` goes to $HOME")
        if name == "git":  # rev:path reads a blob past the path checks
            paths += [w.split(":", 1)[1] for w in args if ":" in w]
        for p in paths:
            if (d := check_path(p, cwd, root, policy)).verdict == "deny":
                return d
        if recursive_read(name, words) or words[:2] == ["git", "add"]:
            dirs = args if name in ("ls", "diff", "git") else args[1:]
            for p in dirs or ["."]:
                if hit := exposes(p, cwd, root, policy):
                    return deny("protected-path", f"recursive read would reach {hit!r}")
        if words[0] == "cd":  # later segments run in the new directory
            cwd = Path(os.path.realpath(cwd / os.path.expanduser(words[1])))
    if asks:
        return Decision(
            "ask", "irreversible", f"needs human confirmation: {', '.join(asks)}"
        )
    return ALLOW


def recursive_read(name: str, words: list[str]) -> bool:
    if name == "rg":
        return True
    flags = {"grep": "rR", "ls": "R", "diff": "r"}.get(name)
    return bool(flags) and any(
        w in ("--recursive", "--dereference-recursive")
        or (w[:1] == "-" and w[:2] != "--" and any(c in w[1:] for c in flags or ""))
        for w in words[1:]
    )


PATH_FIELDS = ("file_path", "notebook_path", "path")


def decide_tool(
    tool: str, tool_input: Mapping, cwd: Path, root: Path, policy: Policy, agent: Agent
) -> Decision:
    if tool in agent.tools_deny:
        return deny("tool-denied", f"{tool} is in tools.deny")
    if tool.startswith("mcp__"):
        if not any(fnmatch.fnmatchcase(tool, p) for p in agent.mcp_allow):
            return deny("mcp-not-allowlisted", f"{tool} is not in mcp.allow")
        return ALLOW
    if tool == "Bash":
        return decide_bash(str(tool_input.get("command", "")), cwd, root, policy, agent)
    for field in PATH_FIELDS:
        if isinstance(v := tool_input.get(field), str) and v:
            if (d := check_path(v, cwd, root, policy)).verdict == "deny":
                return d
    if tool in ("Glob", "Grep") and not tool_input.get("path"):
        return check_path(".", cwd, root, policy)
    return ALLOW


def resolve_agent(name: str, policy: Policy) -> Agent | None:
    return policy.agents.get(name)
