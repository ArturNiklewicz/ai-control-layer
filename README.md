# AI Control Layer

Hybrid guardrails for agentic AI (HackYeah 2026). It sits between a coding agent (Claude Code), its tools/MCP servers and LLMs, and enforces one central policy:

- personal data never reaches a model unless a human consented,
- the agent cannot leave the repo,
- untrusted content cannot steer the agent,
- every decision is audited.

```
 human ──login (TTY + age key + "yes")──► consent (sops-sealed, 8 h)
                                             │
 document ──scan──► PESEL/NIP/REGON/IBAN/card/ID (checksums)   deterministic
                 └► names, addresses (local LLM, private net)  semantic
                          │
              ┌───────────┴────────────┬──────────────┐
            block                  anonymize      pseudonymize
        (secrets, cards)            [OSOBA]       [OSOBA_1] ↔ sops vault
                                       └── no consent → content withheld

 Claude Code ──hook──► command whitelist · repo-only paths · rm/commit = ask
                       roles · PII + injection in prompts, reads, writes
 agent ↔ MCP ──proxy─► tool allowlist · PII + injection in args and results
 container  ─kernel─► only /repo mounted · secrets absent · rules read-only
                       egress default-deny (model API + local LLM only)
                              │
            policy.toml (live reload) · signatures.json (attack feed)
            .guard/audit.jsonl (no PII values) → guard report
```

## Layers

| Layer             | Where                    | Guarantees                                               |
| ----------------- | ------------------------ | -------------------------------------------------------- |
| Container sandbox | `src/guard/sandbox/`     | kernel boundary: files, network, processes, capabilities |
| Hook              | `src/guard/hook.py`      | semantic decision per agent action; fails closed         |
| MCP proxy         | `src/guard/mcp_proxy.py` | tool allowlist, input/output screening                   |
| Human CLI         | `src/guard/cli.py`       | consent, (pseudo)anonymization, vault, report            |

The design and threat model are in [`src/guard/adr/0001-agent-isolation.md`](src/guard/adr/0001-agent-isolation.md), with Mermaid diagrams.

## Quick start

```bash
uv sync
sops decrypt secrets.env > .env                      # needs the age key

uv run python -m src.guard.cli login                 # human only: TTY + age key + consent
uv run python -m src.guard.cli scan docs/            # what PII is there (counts only)
uv run python -m src.guard.cli pseudonymize raw.txt -o clean/raw.txt
uv run python -m src.guard.cli restore clean/raw.txt # key holder only
uv run python -m src.guard.cli report                # security / management summary

src/guard/sandbox/run.sh login                       # once: Claude login inside the box
src/guard/sandbox/run.sh                             # Claude Code in the sandbox
src/guard/sandbox/run.sh selftest                    # attack tests + suite inside the box
```

To wire the hook into Claude Code, add this under `"hooks"` in `.claude/settings.local.json`:

```json
"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "cd \"$CLAUDE_PROJECT_DIR\" && uv run -q python -m src.guard.hook"}]}],
"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "cd \"$CLAUDE_PROJECT_DIR\" && uv run -q python -m src.guard.hook"}]}]
```

## Policy

The policy lives in [`src/guard/policy.toml`](src/guard/policy.toml) and is re-read on every call, so edits apply without a restart. An invalid policy denies everything.

| Setting                                  | Values                                                            |
| ---------------------------------------- | ----------------------------------------------------------------- |
| `mode`                                   | `enforce` / `monitor` (log `would_deny`, block nothing)           |
| `pii.default`, `pii.kinds.*`             | `off` / `anonymize` / `pseudonymize` / `block` per data kind      |
| `pii.semantic_on_error`                  | `fail_closed` / `regex_only`                                      |
| `injection.*`                            | `off` / `warn` / `block` per channel (prompt, reads, tool output) |
| `commands.allow`, `.ask`, `.deny_tokens` | command whitelist, human-confirmed actions                        |
| `paths.deny`, `tools.deny`, `mcp.allow`  | protected files, tools, MCP tools                                 |
| `agents.<name>`                          | per-role overrides; unknown identity is denied                    |

Attack signatures are in [`src/guard/signatures.json`](src/guard/signatures.json): prompt injection (EN/PL), chat-template spoofing, hidden Unicode, exfiltration, `curl|sh`, reverse shells, pickle/`torch.load`, `trust_remote_code`, ShadowRay. The file can be swapped for an externally managed feed with the same schema.

## Tests

```bash
uv run pytest                                          # fast: unit + contract (~4 s)
uv run --env-file .env pytest -m "integration and not agent" -s   # real processes, narrated (~1 min)
uv run pytest -m "integration and negative" -s         # attacks only
uv run pytest -m "integration and pii" -s              # one control area
uv run pytest -m agent -s                              # real Claude Code + guard (spends tokens)
uv run pytest --markers                                # all tags
```

Tags:

- **Run type:** `integration`, `live` (local LLM), `live_api`, `docker`, `agent`.
- **Outcome:** `positive`, `negative`.
- **Control area:** `pii`, `consent`, `vault`, `hook`, `mcp`, `sandbox`, `injection`, `policy`, `audit`.

When a resource (Docker, the DGX model, an API key) is missing, those tests are skipped with the reason shown.

The integration tests use a fictional Polish corpus in `tests/integration/corpus/`. No real personal data is used.

## Requirements

- Python ≥ 3.12 and `uv`
- `sops` + `age`, needed for consent and the vault
- Docker, for the sandbox
- an OpenAI-compatible local LLM on a private network, for semantic NER. Default: vLLM `qwen3-35b` reached over tailscale. Public hosts are refused.
