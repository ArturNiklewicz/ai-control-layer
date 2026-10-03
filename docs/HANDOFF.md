# HANDOFF — AI Control Layer

Context for the next session: (1) evaluate, (2) review, (3) finish the implementation, (4) add integrations for common agentic harnesses.

## Where things are

- Repo: `~/Developer/HackYeah/ai-control-layer`, GitHub `ArturNiklewicz/ai-control-layer` (private), branch `main`.
- This repo is separate from the team repo `~/Developer/HackYeah`, which holds the other challenges.
- The team repo excludes this directory only locally, via `.git/info/exclude`.
- Pre-split commit history is on the team branch `artur/shared-core`.
- Challenge: HackYeah "AI Control Layer". Scoring:
  - guardrail robustness 30%
  - architecture/performance 20%
  - security reporting 20%
  - test suite 15%
  - implementability 15%
- Judges will:
  - run the test suite,
  - type ad-hoc prompts,
  - edit the policy live,
  - ask for performance telemetry.
- Read first: `README.md`, `src/guard/adr/0001-agent-isolation.md` (threat model, elements E1–E17, flows F1–F12, risks R1–R6).

## Architecture (as built)

```
L0 Docker Desktop VM
L1 container  src/guard/sandbox/   only /repo mounted; .env→/dev/null; .git .claude src/guard :ro;
                                   egress default-deny v4+v6, no DNS, allowlist = api.anthropic.com + DGX vLLM;
                                   setpriv → host uid, caps empty, no_new_privs; ro rootfs; pids/mem/cpu limits
L2 hook       src/guard/hook.py    Claude Code PreToolUse + UserPromptSubmit; restrict-only; fail-closed
L3 mcp proxy  src/guard/mcp_proxy.py  stdio JSON-RPC; tools/list filter; args + results screened
L4 human CLI  src/guard/cli.py     login (TTY + age-key proof + "t") → sops-sealed consent 8h;
                                   scan / anonymize / pseudonymize / restore / report
```

Pure core, stdlib only, enforced by `tests/test_boundaries.py`:

| File                      | Role                                                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pii.py`                  | checksummed PL detectors: PESEL, NIP, REGON, IBAN, card, ID card; secrets, email, phone. Local-LLM NER for PERSON/ADDRESS with Polish stem matching. Masking. |
| `commands.py`             | whitelist and repo confinement                                                                                                                                |
| `scrub.py`                | block → consent → mask                                                                                                                                        |
| `injection.py`            | signature matching; feed in `signatures.json`                                                                                                                 |
| `policy.py`               | parses `policy.toml`                                                                                                                                          |
| `consent.py`, `report.py` | consent model, report rendering                                                                                                                               |

Shells: `vault.py` (sops `--config /dev/null`), `audit.py` (`.guard/audit.jsonl`, never PII values).

Shared helpers copied from the team repo:

- `src/result.py`: `Ok`/`Err`, covariant; `attempt(f, catch, to_err)`.
- `src/llm.py`: `ProviderError` kinds, `completer` with token usage, `embedder`.

Invariants (each has a test):

- The hook only restricts; it never grants.
- An invalid policy, crash or unknown identity → deny.
- The policy is re-read on every call.
- The active policy file and feed are always self-protected.
- No consent → PII is withheld, never transformed silently.
- NER is only sent to private/tailnet hosts.
- Identity comes from the harness (`agent_type` / `GUARD_AGENT`).

## Infra / environment

- Local LLM: vLLM `qwen3-35b` (Qwen3.6-35B-A3B-FP8) at `http://100.117.237.101:8006/v1` (DGX-A, tailnet). Send `chat_template_kwargs.enable_thinking=false`. About 10 s per document.
- `secrets.env`: sops-encrypted, holds only `OPENAI_API_KEY` and `EMBED_MODEL`. Decrypt with `sops decrypt secrets.env > .env`. Never print values.
- age recipient: `age1umrllqac6f5t9uehkcmf03htaxdcgzl240gyhzjv60eykkkkputq505mq2` (key at `~/.config/sops/age/keys.txt`).
- Docker Desktop: the credential helper is not on PATH; `run.sh` appends `/Applications/Docker.app/Contents/Resources/bin`.
- Claude Code 2.1.288 is installed in the image. The `claude` CLI on the host is used by the `-m agent` tests (model haiku).

## Commands

```
uv run pytest                                                    # 173 passed, rest skipped (~4 s)
uv run --env-file .env pytest -m "integration and not agent" -s  # 80 narrated real-process tests (~1-2 min)
uv run pytest -m agent -s                                        # 5 real Claude Code + guard (tokens)
uv run pytest -m "integration and negative" -s                   # attacks only; tags: --markers
src/guard/sandbox/run.sh selftest                                # suite + 23 attack tests inside the container
uvx basedpyright src tests                                       # 0 errors
```

Markers are registered in `tests/conftest.py`. Integration tests skip with a reason when Docker, DGX or the key is missing. The corpus in `tests/integration/corpus/` is fictional with checksum-valid IDs. `.py` samples are stored as `.txt`.

## Status vs the challenge

| Requirement                                           | Status                                                                     |
| ----------------------------------------------------- | -------------------------------------------------------------------------- |
| Central policy, thresholds, block/redact, live reload | ✅ `policy.toml`. Allowed-models list missing.                             |
| Deterministic controls (PII, secrets, authz)          | ✅                                                                         |
| Semantic (AI) controls                                | ⚠️ NER only. No LLM-judge for injection/output yet (ADR-0004).             |
| Budget / resource governance                          | ❌ No LLM gateway or token/cost budgets (ADR-0003). Only container limits. |
| Historical attack mitigation, external feed           | ✅ `signatures.json`, swappable. No remote fetch, signing or versioning.   |
| Reporting + exportable audit                          | ⚠️ CLI `report` + JSONL. **No interactive dashboard UI.**                  |
| Self-testing suite (positive + negative)              | ✅                                                                         |
| Architecture diagram                                  | ✅ Mermaid in ADR-0001.                                                    |
| Performance telemetry                                 | ⚠️ Hook `latency_ms` p50/p95 in the report. No gateway throughput numbers. |

## Known gaps / risks (prioritized)

1. **R2 audit tamper:** `.guard/` is writable inside the container (same uid). Fix with an append-only sidecar or by shipping events to Langfuse on DGX-B (ADR-0002).
2. **Budgets:** an OpenAI-compatible gateway (FastAPI is not a dependency here yet; stdlib `http.server` or add fastapi+uvicorn). It needs:
   - per-principal/model token and cost budgets from `completer` usage,
   - an allowed-models list,
   - PII/injection checks on request and response,
   - streaming pass-through,
   - local vs commercial pricing table.
3. **LLM judge:** semantic injection/jailbreak scoring on the DGX model. Threshold in the policy. Signatures run first and the judge only on residual risk (latency).
4. **Dashboard:**
   - **For management:** posture, blocks, cost.
   - **For security:** rules, agents, signatures, export.
   - Build it as a single HTML artifact reading `audit.jsonl`, or a tiny served page.
5. **MCP proxy:**
   - outputs are anonymized, not pseudonymized;
   - the consent grant is read once per session;
   - no MCP servers are baked into the image.
6. **Hook heuristics:**
   - `read_targets` only sees file paths that appear in the Bash command text;
   - writes are scanned only for `block` kinds;
   - `restore` returns canonical (nominative) forms.
7. **NER:**
   - recall was measured only on the 2-document corpus;
   - no false-positive benchmark;
   - single-word names are not stem-matched.
8. **Supply chain:** the Claude installer in the Dockerfile is not version- or checksum-pinned.
9. **Injection signatures:** regexes are tuned on a small set. Benign false-positive risk is untested at scale.

## Next steps

### 1. Evaluation (separate from deterministic tests)

- Build `eval/` datasets:
  - PII: PL documents with labelled spans → precision/recall per kind, regex vs hybrid;
  - injection: jailbreak and benign prompts, EN/PL, e.g. public sets such as deepset/prompt-injections, JailbreakBench; check licenses → TPR/FPR per signature and for the judge;
  - latency: p50/p95 per layer.
- Output: one JSON/markdown table per run. Do not gate CI on the model-based metrics.

### 2. Review

Adversarial review (refuter agents) of:

- `commands.py` bypasses: shell tricks, unicode, argument injection into allowed tools such as `git` `--upload-pack` and `rg --pre`;
- `hook.py` fail-closed paths;
- `mcp_proxy.py` JSON-RPC edge cases: batch requests, notifications, ids;
- vault/consent tampering;
- sandbox escapes.

Each finding gets a regression test.

### 3. Finish the implementation

In this order: gateway with budgets + allowed models → LLM judge → dashboard → audit sidecar (R2) → pinned installer.

### 4. Integrations with agentic harnesses

Integration points per harness (verify against current docs via ctx7 before building):

| Harness                                                                                                          | Integration point                                                                                      |
| ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Claude Code                                                                                                      | ✅ hooks + MCP proxy + sandbox. Add `.claude/settings.json` template and PostToolUse output screening. |
| Claude Agent SDK (py/ts)                                                                                         | `can_use_tool` / hooks callback → `hook.evaluate`; tool-result filter                                  |
| OpenAI-compatible clients (OpenAI SDK, LiteLLM, LangChain, LlamaIndex, CrewAI, AutoGen, smolagents, pydantic-ai) | via the **gateway** (`base_url` swap) — one integration covers most                                    |
| LangChain / LangGraph                                                                                            | callback handler or tool wrapper for tool-level decisions                                              |
| OpenAI Agents SDK                                                                                                | input/output guardrails API                                                                            |
| MCP clients (Cursor, Windsurf, Cline, Continue, Zed, VS Code Copilot agent)                                      | `mcp_proxy` wrapping in each client's MCP config                                                       |
| Codex CLI / Gemini CLI / Aider / OpenCode                                                                        | sandbox container + gateway (`base_url`); native hook/policy where available                           |
| Cursor / Cline                                                                                                   | hook mechanisms (Cursor hooks, Cline `.clinerules`) — check current docs                               |

Design rule: keep one policy and one decision core (`commands.decide_tool`, `scrub`, `injection.scan`). Each harness is a thin adapter (`src/guard/adapters/<harness>.py`) with a contract test that feeds the harness's real payload shape. Add a `harness` marker and an `integration and harness` test per adapter.

## Conventions (user preferences)

- **Replies:** chat in Polish, terse; ASCII diagrams welcome. Comments in code: minimal; the user rejected verbose comments. Code and identifiers in English.
- **Code style:**
  - minimal code; mark shortcuts with `# ponytail:` plus ceiling and upgrade path;
  - functional core / imperative shell;
  - `Result` for expected failures; bugs propagate.
- **Tests:**
  - every bug found gets a regression test;
  - integration tests narrate via the `say` fixture (`pytest -s`).
- **Commits:**
  - Conventional Commits, ending with the `Co-Authored-By: Claude …` line;
  - commit only when asked; push is done by the user or on explicit request.
- **Human-only steps** (login, OAuth, push) go into `docs/scratchpad/SCRATCHPAD.md` (gitignored), not into chat only.
