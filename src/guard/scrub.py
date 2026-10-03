"""Policy applied to detected PII: one pure decision used by CLI, hook and MCP proxy.

spans --policy.action(kind)--> block?  -> Err(Blocked)
                               consent? -> Err(NoConsent)   (fail closed)
                               mask     -> Ok(Scrubbed)
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, replace

from src.guard.pii import Span, Vault, label, mask, pseudonymizer
from src.guard.policy import Policy
from src.result import Err, Ok, Result


@dataclass(frozen=True, slots=True)
class Scrubbed:
    text: str
    vault: dict[str, str]  # extended with new pseudonyms; caller persists it
    counts: dict[str, int]  # kind -> occurrences (safe to log: no values)


@dataclass(frozen=True, slots=True)
class Blocked:
    kinds: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NoConsent:
    actions: tuple[str, ...]
    kinds: tuple[str, ...]


def scrub(
    text: str,
    spans: list[Span],
    policy: Policy,
    vault: Vault,
    consented: Callable[[str], bool],
) -> Result[Scrubbed, Blocked | NoConsent]:
    acted = [(s, policy.action(s.kind)) for s in spans]
    acted = [(s, a) for s, a in acted if a != "off"]
    counts = dict(Counter(s.kind for s, _ in acted))
    if blocked := sorted({s.kind for s, a in acted if a == "block"}):
        return Err(Blocked(tuple(blocked)))
    needed = sorted({a for _, a in acted})
    if missing := [a for a in needed if not consented(a)]:
        return Err(NoConsent(tuple(missing), tuple(sorted(counts))))
    pseudo, new_vault = pseudonymizer(vault)
    action_of = {(s.start, s.end): a for s, a in acted}

    def token(s: Span) -> str:
        return (
            pseudo(s)
            if action_of[(s.start, s.end)] == "pseudonymize"
            else f"[{label(s.kind)}]"
        )

    return Ok(Scrubbed(mask(text, [s for s, _ in acted], token), new_vault, counts))


def as_anonymize(policy: Policy) -> Policy:
    """Same policy, but every reversible action becomes irreversible."""
    swap = {k: ("anonymize" if v == "pseudonymize" else v) for k, v in policy.pii_kinds.items()}
    default = "anonymize" if policy.pii_default == "pseudonymize" else policy.pii_default
    return replace(policy, pii_default=default, pii_kinds=swap)
