# Sandbox agenta (ADR-0001). Kod repo nie jest w obrazie — run.sh montuje go jako /repo.
FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

# rg = Grep w Claude Code; iptables = firewall; curl = pobranie Claude Code. Kasujemy tylko indeks apt.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ripgrep iptables ca-certificates curl bash \
 && rm -rf /var/lib/apt/lists/*

# uv (Astral) = menedżer pakietów Pythona; jeden plik binarny z oficjalnego obrazu.
COPY --from=ghcr.io/astral-sh/uv:0.9.4@sha256:c4089b0085cf4d38e38d5cdaa5e57752c1878a6f41f2e3a3a234dc5f23942cb4 /uv /usr/local/bin/uv

# Claude Code: natywny plik z pakietu npm (bez Node), wersja przypięta, sha512 z `npm view <pkg>@<ver> dist.integrity`.
# Niezgodna suma = build pada. Aktualizacja: nowa wersja + nowe sumy obu architektur (docs/HANDOFF.md).
# ponytail: ufamy rejestrowi npm przy PIERWSZYM pobraniu sum (TOFU); pełna ścieżka = podpis/provenance (`npm audit signatures`).
ARG TARGETARCH
ARG CLAUDE_VERSION=2.1.288
RUN case "$TARGETARCH" in \
      amd64) a=x64;   sri=sha512-m80cJZimlKjRiwveadPgAfubhbmwa2nF85gg20WbjnHl6QKMad0bXiMp6JNcPeSZsr0N1KJ/wkR34rRoiyyYyg== ;; \
      arm64) a=arm64; sri=sha512-sP12YSgo3CQw4gM+C0AaIAHawW1xN4j2OKlGZFobFE2UG5eMRVQslQug8bXuVsldI1F+HT3vvfRNB3mdDge18A== ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL --retry 20 --retry-all-errors -C - -o /tmp/cc.tgz "https://registry.npmjs.org/@anthropic-ai/claude-code-linux-$a/-/claude-code-linux-$a-$CLAUDE_VERSION.tgz" \
 && python3 -c "import base64,hashlib,sys; d=hashlib.sha512(open('/tmp/cc.tgz','rb').read()).digest(); sys.exit(0 if 'sha512-'+base64.b64encode(d).decode()==sys.argv[1] else 'claude-code integrity mismatch')" "$sri" \
 && tar -xzf /tmp/cc.tgz -C /tmp package/claude \
 && install -m 0755 /tmp/package/claude /usr/local/bin/claude \
 && rm -rf /tmp/cc.tgz /tmp/package

# Zależności w buildzie (runtime bez sieci). venv w /opt, bo /repo/.venv to venv hosta (macOS).
# a+rX: odczyt dla wszystkich, wykonanie tylko katalogi i pliki już wykonywalne (agent to uid 501).
COPY pyproject.toml uv.lock /build/
RUN cd /build && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project --no-cache \
 && chmod -R a+rX /opt/venv && rm -rf /build

# UV_*: tylko to, co w obrazie (bez sync, locka, sieci). Bez __pycache__ (src/guard jest read-only).
# Claude: bez autoupdate i telemetrii (allowlista = tylko API). GUARD_SANDBOX: włącza testy ataku.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_NO_SYNC=1 UV_FROZEN=1 UV_OFFLINE=1 \
    UV_CACHE_DIR=/tmp/uv-cache PYTHONDONTWRITEBYTECODE=1 \
    DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    CLAUDE_CONFIG_DIR=/home/agent/.claude HOME=/home/agent GUARD_SANDBOX=1

# Każda komenda idzie przez entrypoint: firewall, potem zrzut do uid agenta bez uprawnień.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["claude"]
