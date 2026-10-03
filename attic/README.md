# attic

Superseded by the anonymizing proxy (`src/guard/gateway.py` `/v1/messages`, engine in
`src/guard/anonymizer.py`): personal data is pseudonymized automatically before anything
leaves the machine, so a human consent step before anonymization no longer gates anything.

| file | was | replaced by |
|---|---|---|
| `src/guard/consent.py` | consent grant model (TTY + age key, 8 h TTL, host nonce) | — (anonymization is unconditional) |
| `src/guard/scrub.py` | block → consent → mask decision per document | `Anonymizer.pseudonymize_many` |
| `src/guard/vault.py` | sops+age sealed vault and grant, hash-pinned | host-only `anonymizer.json` (0600, outside the repo) |
| `tests/test_consent_scrub_vault.py`, `tests/integration/test_consent_pii.py` | their tests | `tests/test_anthropic_proxy.py` |

Not collected by pytest, not type-checked. Delete once nobody asks for the consent flow.
