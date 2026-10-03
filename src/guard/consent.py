"""Consent before any anonymization / pseudonymization.

A grant exists only after `guard login`: interactive TTY (an agent's shell has none), proof of
the age private key, and an explicit "yes". It is sealed with sops and expires.
No valid grant + PII found => callers block (fail closed), they never transform silently.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

ACTIONS = ("anonymize", "pseudonymize")


@dataclass(frozen=True, slots=True)
class Grant:
    user: str
    actions: frozenset[str]
    granted_at: datetime
    expires_at: datetime
    method: str  # how the user was authenticated, for the audit trail


def grant(
    user: str, actions: frozenset[str], now: datetime, hours: float, method: str
) -> Grant:
    return Grant(
        user, actions & frozenset(ACTIONS), now, now + timedelta(hours=hours), method
    )


def allows(g: Grant | None, action: str, now: datetime) -> bool:
    return g is not None and action in g.actions and g.granted_at <= now < g.expires_at


def to_json(g: Grant) -> dict:
    return {
        "user": g.user,
        "actions": sorted(g.actions),
        "granted_at": g.granted_at.isoformat(),
        "expires_at": g.expires_at.isoformat(),
        "method": g.method,
    }


def from_json(raw: Mapping) -> Grant | None:
    try:
        return Grant(
            str(raw["user"]),
            frozenset(raw["actions"]) & frozenset(ACTIONS),
            datetime.fromisoformat(raw["granted_at"]),
            datetime.fromisoformat(raw["expires_at"]),
            str(raw.get("method", "")),
        )
    except (KeyError, TypeError, ValueError):
        return None  # unreadable grant == no grant
