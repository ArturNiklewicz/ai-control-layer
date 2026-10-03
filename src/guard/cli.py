"""Human-facing guard CLI.

uv run python -m src.guard.cli scan FILE...          # what PII is there (counts, no values)
uv run python -m src.guard.cli anonymize PATH [-o OUT]     # irreversible  [OSOBA]
uv run python -m src.guard.cli pseudonymize PATH [-o OUT]  # reversible    [OSOBA_1]
uv run python -m src.guard.cli restore FILE          # pseudonyms -> originals
uv run python -m src.guard.cli report                # audit summary for security / management
uv run python -m src.guard.cli dashboard [-o PATH] [--open]  # interactive HTML report (offline)

anonymize/pseudonymize/restore use the proxy's engine and vault (one token space: a document
pseudonymized here and one the proxy saw name the same person the same way).
"""

import argparse
import hashlib
import ipaddress
import os
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from src.guard import audit
from src.guard.injection import load_feed, scan
from src.guard.pii import PRIORITY, Span, detect, non_overlapping, semantic_spans
from src.guard.policy import Policy, load
from src.guard.fsio import atomic_write
from src.result import Err, Ok, Result

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
NO_THINKING = {"chat_template_kwargs": {"enable_thinking": False}}  # NER needs no reasoning
TAILNET = ipaddress.ip_network("100.64.0.0/10")  # tailscale CGNAT range: private to us


def now() -> datetime:
    return datetime.now(UTC)


def fail(msg: str) -> int:
    print(f"guard: {msg}", file=sys.stderr)
    return 1


def is_local(url: str) -> bool:
    """PII must never reach a public LLM: every address the host resolves to must be private."""
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        addrs = {ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):
        return False
    return bool(addrs) and all(
        a.is_private or a.is_loopback or a in TAILNET for a in addrs
    )


def state() -> Path:
    """Host-only state (anonymizer vault and caches, spend ledger) lives outside the repo; the
    sandbox never mounts it."""
    base = Path(os.environ.get("GUARD_STATE") or Path.home() / ".config" / "guard")
    return base / hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]


# --- detection ---


def find_spans(text: str, policy: Policy) -> Result[list[Span], str]:
    spans = detect(text)
    if not policy.semantic:
        return Ok(spans)
    if not is_local(policy.llm_base_url):
        if policy.semantic_fail_closed:
            return Err(
                f"llm.base_url {policy.llm_base_url!r} is not private; refusing to send PII"
            )
        return Ok(spans)
    from openai import OpenAI  # only when semantic detection runs: core stays SDK-free

    from src.llm import completer

    client = OpenAI(
        base_url=policy.llm_base_url, api_key=os.environ.get("GUARD_LLM_KEY", "local")
    )
    complete = completer(client, policy.llm_model)
    match semantic_spans(text, lambda m, **kw: complete(m, extra_body=NO_THINKING, **kw).map(lambda c: c.text)):
        case Ok(found):
            return Ok(
                non_overlapping(spans + found, PRIORITY | {"PERSON": 90, "ADDRESS": 91})
            )
        case Err(e):
            if policy.semantic_fail_closed:
                return Err(
                    f"semantic detector failed ({e}); semantic_on_error=fail_closed"
                )
            print(
                f"guard: warning: semantic detector failed, regex only ({e})",
                file=sys.stderr,
            )
            return Ok(spans)


def files_of(path: Path) -> list[Path]:
    return (
        sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    )


def cmd_scan(policy: Policy, args) -> int:
    feed = load_feed(ROOT / policy.feed_path)
    for f in (f for p in args.paths for f in files_of(Path(p))):
        text = f.read_text(errors="replace")
        match find_spans(text, policy):
            case Err(e):
                return fail(e)
            case Ok(spans):
                counts = Counter(s.kind for s in spans)
                hits = (
                    [h.id for h in scan(text, feed.value)]
                    if isinstance(feed, Ok)
                    else []
                )
                plan = {k: policy.action(k) for k in counts}
                print(
                    f"{f}: {dict(counts) or 'brak PII'}  akcje={plan}  sygnatury={hits or '-'}"
                )
    return 0


# --- transform ---


def cmd_transform(policy: Policy, args) -> int:
    from dataclasses import replace

    from src.guard.gateway import engine

    mode = args.cmd
    pol = policy if mode == "pseudonymize" else replace(
        policy, pii_default="anonymize", pii_kinds={k: "block" if v == "block" else "anonymize" for k, v in policy.pii_kinds.items()}
    )  # fmt: skip
    eng, src = engine(policy), Path(args.path)
    out_root = Path(args.out) if args.out else None
    status = 0
    for f in files_of(src):
        dest = (
            (out_root / f.relative_to(src) if src.is_dir() else out_root)
            if out_root
            else f.with_name(f"{f.stem}.{mode[:4]}{f.suffix}")
        )
        text = f.read_text(errors="replace")
        event = {"event": mode, "file": hashlib.sha256(os.path.relpath(f, ROOT).encode()).hexdigest()[:12]}
        match eng.pseudonymize_many([text], pol):
            case Ok((done, counts, _)):
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(done[text])
                audit.record(ROOT, event | {"verdict": "allow", "pii": dict(counts)}, now())
                print(f"{f} -> {dest}  {dict(counts) or 'brak PII'}")
            case Err(e):
                audit.record(ROOT, event | {"verdict": "deny", "rule": "detector-error"}, now())
                status = fail(f"{f}: {e}")
    eng.save()
    return status


def cmd_restore(policy: Policy, args) -> int:
    from src.guard.gateway import engine

    sys.stdout.write(engine(policy).restore(Path(args.path).read_text()))
    audit.record(ROOT, {"event": "restore", "verdict": "allow"}, now())
    return 0


def cmd_report(policy: Policy, args) -> int:
    from src.guard.report import render

    print(render(audit.read(ROOT), now()))
    return 0


def cmd_dashboard(policy: Policy, args) -> int:
    import webbrowser

    from src.guard.report import render_html

    out = Path(args.out) if args.out else ROOT / ".guard" / "dashboard.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(out, render_html(audit.read(ROOT), now()))
    out.chmod(0o600)
    print(out)
    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="guard",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("report")
    d = sub.add_parser("dashboard")
    d.add_argument("-o", "--out")
    d.add_argument("--open", action="store_true")
    s = sub.add_parser("scan")
    s.add_argument("paths", nargs="+")
    for name in ("anonymize", "pseudonymize"):
        t = sub.add_parser(name)
        t.add_argument("path")
        t.add_argument("-o", "--out")
    r = sub.add_parser("restore")
    r.add_argument("path")
    args = ap.parse_args(argv)
    match load(Path(os.environ.get("GUARD_POLICY") or ROOT / "src/guard/policy.toml")):
        case Err(e):
            return fail(e.detail)
        case Ok(policy):
            handler = {"scan": cmd_scan, "report": cmd_report, "dashboard": cmd_dashboard,
                       "anonymize": cmd_transform, "pseudonymize": cmd_transform, "restore": cmd_restore}  # fmt: skip
            return handler[args.cmd](policy, args)


if __name__ == "__main__":
    sys.exit(main())
