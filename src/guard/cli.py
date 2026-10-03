"""Human-facing guard CLI.

uv run python -m src.guard.cli login                 # authenticate + consent (TTY only)
uv run python -m src.guard.cli scan FILE...          # what PII is there (counts, no values)
uv run python -m src.guard.cli anonymize PATH [-o OUT]     # irreversible  [OSOBA]
uv run python -m src.guard.cli pseudonymize PATH [-o OUT]  # reversible    [OSOBA_1]
uv run python -m src.guard.cli restore FILE          # pseudonyms -> originals (key holder)
uv run python -m src.guard.cli report                # audit summary for security / management
uv run python -m src.guard.cli dashboard [-o PATH] [--open]  # interactive HTML report (offline)
uv run python -m src.guard.cli logout
"""

import argparse
import getpass
import hashlib
import ipaddress
import os
import secrets
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from src.guard import audit
from src.guard.consent import ACTIONS, Grant, allows, from_json, grant, to_json
from src.guard.injection import load_feed, scan
from src.guard.pii import (
    PRIORITY,
    Span,
    detect,
    non_overlapping,
    restore,
    semantic_spans,
)
from src.guard.policy import Policy, load
from src.guard.scrub import Blocked, NoConsent, as_anonymize, scrub
from src.guard.vault import atomic_write, load_pinned, load_sealed, save_pinned, save_sealed
from src.result import Err, Ok, Result

ROOT = Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()).resolve()
GRANT = ROOT / ".guard" / "consent.sops.json"
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
    """Host-only secrets (grant nonce, vault pin) live outside the repo; the sandbox never mounts them."""
    base = Path(os.environ.get("GUARD_STATE") or Path.home() / ".config" / "guard")
    return base / hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]


def read_nonce() -> str:
    p = state() / "grant-nonce"
    return p.read_text().strip() if p.is_file() else ""


def current_grant(hours: float | None = None) -> Grant | None:
    if hours is None:
        match load(Path(os.environ.get("GUARD_POLICY") or ROOT / "src/guard/policy.toml")):
            case Ok(p):
                hours = p.consent_hours
            case _:
                return None
    match load_sealed(GRANT):
        case Ok(raw) if raw:
            return from_json(raw, read_nonce(), hours)
        case _:
            return None  # missing, tampered, forged or undecryptable == no consent


def vault_pin() -> Path:
    return state() / "vault-hash"


# --- login: the only way to create consent ---


def cmd_login(policy: Policy, args) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return fail("login needs an interactive terminal; an agent cannot give consent")
    user = getpass.getuser()
    nonce = {"challenge": secrets.token_hex(16)}
    probe = ROOT / ".guard" / "challenge.sops.json"
    proof = save_sealed(probe, nonce, policy.age_recipient).bind(
        lambda p: load_sealed(p)
    )
    probe.unlink(missing_ok=True)
    if proof != Ok(nonce):
        return fail(f"authentication failed: cannot decrypt with the age key ({proof})")
    kinds = ", ".join(f"{k}={v}" for k, v in sorted(policy.pii_kinds.items()))
    print(
        f"Użytkownik: {user} (klucz age zweryfikowany)\n"
        f"Zgoda obejmuje: {', '.join(ACTIONS)} na {policy.consent_hours:g} h.\n"
        f"Domyślnie: {policy.pii_default}; wyjątki: {kinds}\n"
        "Dane osobowe zostaną zastąpione; oryginały pseudonimów trafią do zaszyfrowanego sejfu."
    )
    if input("Czy wyrażasz zgodę? [t/N]: ").strip().lower() not in (
        "t",
        "tak",
        "y",
        "yes",
    ):
        audit.record(ROOT, {"event": "consent", "user": user, "verdict": "deny"}, now())
        return fail("no consent given")
    g = grant(user, frozenset(ACTIONS), now(), policy.consent_hours, "tty+age-key")
    host_nonce = secrets.token_hex(32)
    match save_sealed(GRANT, to_json(g, host_nonce), policy.age_recipient):
        case Err(e):
            return fail(e.detail)
    try:
        state().mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_write(state() / "grant-nonce", host_nonce)
    except OSError as e:
        GRANT.unlink(missing_ok=True)
        return fail(f"cannot store host nonce: {e}")
    audit.record(ROOT, {"event": "consent", "user": user, "verdict": "allow", "actions": sorted(g.actions),
                        "expires_at": g.expires_at.isoformat()}, now())  # fmt: skip
    print(f"Zgoda zapisana do {g.expires_at:%Y-%m-%d %H:%M} UTC.")
    return 0


def cmd_logout(policy: Policy, args) -> int:
    GRANT.unlink(missing_ok=True)
    (state() / "grant-nonce").unlink(missing_ok=True)  # kills every copy of the old grant
    audit.record(
        ROOT,
        {"event": "consent", "verdict": "revoked", "user": getpass.getuser()},
        now(),
    )
    print("Zgoda cofnięta.")
    return 0


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
    mode = args.cmd
    pol = as_anonymize(policy) if mode == "anonymize" else policy
    g, t = current_grant(policy.consent_hours), now()
    if not allows(g, mode, t):
        return fail(
            "no valid consent: the user must run `uv run python -m src.guard.cli login`"
        )
    vault_path = ROOT / policy.vault_path
    vault: dict = {}
    if mode == "pseudonymize":
        match load_pinned(vault_path, vault_pin()):
            case Ok(v):
                vault = v
            case Err(e):
                return fail(f"vault: {e.detail}")
    src = Path(args.path)
    out_root = Path(args.out) if args.out else None
    status = 0
    for f in files_of(src):
        dest = (
            (out_root / f.relative_to(src) if src.is_dir() else out_root)
            if out_root
            else f.with_name(f"{f.stem}.{mode[:4]}{f.suffix}")
        )
        text = f.read_text(errors="replace")
        r = find_spans(text, pol).bind(
            lambda spans: scrub(text, spans, pol, vault, lambda a: allows(g, a, t))  # type: ignore[arg-type]
        )
        event = {"event": mode, "user": g.user if g else None, "file": hashlib.sha256(os.path.relpath(f, ROOT).encode()).hexdigest()[:12]}
        match r:
            case Ok(done):
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(done.text)
                vault = done.vault
                audit.record(ROOT, event | {"verdict": "allow", "pii": done.counts}, t)
                print(f"{f} -> {dest}  {done.counts or 'brak PII'}")
            case Err(Blocked(kinds)):
                audit.record(
                    ROOT,
                    event
                    | {"verdict": "deny", "rule": "pii-block", "kinds": list(kinds)},
                    t,
                )
                status = fail(
                    f"{f}: contains {', '.join(kinds)} (policy: block) — not written"
                )
            case Err(NoConsent(actions, kinds)):
                status = fail(f"{f}: consent missing for {actions}")
            case Err(e):
                audit.record(
                    ROOT, event | {"verdict": "deny", "rule": "detector-error"}, t
                )
                status = fail(f"{f}: {e}")
    if mode == "pseudonymize":
        match save_pinned(vault_path, vault, policy.age_recipient, vault_pin()):
            case Err(e):
                return fail(f"vault not saved: {e.detail}")
    return status


def cmd_restore(policy: Policy, args) -> int:
    g, t = current_grant(policy.consent_hours), now()
    if not allows(g, "pseudonymize", t):
        return fail("no valid consent: run `login` first")
    match load_pinned(ROOT / policy.vault_path, vault_pin()):
        case Ok(vault):
            sys.stdout.write(restore(Path(args.path).read_text(), vault))
            audit.record(
                ROOT,
                {"event": "restore", "user": g.user if g else None, "verdict": "allow"},
                t,
            )
            return 0
        case Err(e):
            return fail(f"vault: {e.detail}")


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
    sub.add_parser("login")
    sub.add_parser("logout")
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
            handler = {"login": cmd_login, "logout": cmd_logout, "scan": cmd_scan, "report": cmd_report, "dashboard": cmd_dashboard,
                       "anonymize": cmd_transform, "pseudonymize": cmd_transform, "restore": cmd_restore}  # fmt: skip
            return handler[args.cmd](policy, args)


if __name__ == "__main__":
    sys.exit(main())
