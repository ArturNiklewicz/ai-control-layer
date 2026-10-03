"""Audit log -> text report: posture for management, rule/agent breakdown for security."""

from collections import Counter
from datetime import datetime, timedelta


def bar(n: int, top: int, width: int = 24) -> str:
    return "█" * max(1, round(width * n / top)) if n else ""


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))] if s else 0.0


def render(events: list[dict], now: datetime, window: timedelta = timedelta(days=1)) -> str:
    since = now - window
    recent = [e for e in events if datetime.fromisoformat(e["ts"]) >= since]
    decisions = [e for e in recent if "verdict" in e and e.get("event") in ("PreToolUse", "UserPromptSubmit", "mcp")]
    verdicts = Counter(e.get("would", e["verdict"]) for e in decisions)
    rules = Counter(e["rule"] for e in decisions if e.get("rule") not in (None, "ok"))
    pii = Counter()
    for e in recent:
        pii.update(e.get("pii") or {})
    sigs = Counter(s for e in recent for s in e.get("signatures", []))
    agents = Counter((e.get("agent", "?"), e.get("would", e["verdict"])) for e in decisions)
    lat = [e["latency_ms"] for e in decisions if "latency_ms" in e]
    total = sum(verdicts.values()) or 1
    lines = [
        f"AI CONTROL LAYER — last {window} (until {now:%Y-%m-%d %H:%M} UTC)",
        "",
        f"decisions {sum(verdicts.values())}   allow {verdicts['allow']}   ask {verdicts['ask']}   "
        f"deny {verdicts['deny']}   block-rate {verdicts['deny'] / total:.0%}",
        f"hook latency  p50 {pct(lat, .5):.1f} ms   p95 {pct(lat, .95):.1f} ms",
        "",
    ]
    for title, counter in (("denials by rule", rules), ("PII detected", pii), ("attack signatures", sigs)):
        lines.append(title)
        top = max(counter.values(), default=1)
        lines += [f"  {k:<22} {n:>5} {bar(n, top)}" for k, n in counter.most_common(10)] or ["  -"]
        lines.append("")
    lines.append("agents (verdict)")
    lines += [f"  {a:<12} {v:<6} {n:>5}" for (a, v), n in sorted(agents.items())] or ["  -"]
    consent = [e for e in recent if e.get("event") == "consent"]
    lines += ["", "consent"] + ([f"  {e['ts'][:19]}  {e.get('user')}  {e['verdict']}" for e in consent[-5:]] or ["  -"])
    return "\n".join(lines)
