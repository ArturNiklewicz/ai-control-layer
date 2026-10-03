# Sandbox agenta (ADR-0001). Kod repo nie jest w obrazie — run.sh montuje go jako /repo.
FROM python:3.13-slim-bookworm

# rg = Grep w Claude Code; iptables = firewall; curl+bash = instalator. Kasujemy tylko indeks apt.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ripgrep iptables ca-certificates curl bash \
 && rm -rf /var/lib/apt/lists/*

# uv (Astral) = menedżer pakietów Pythona; jeden plik binarny z oficjalnego obrazu.
COPY --from=ghcr.io/astral-sh/uv:0.9.4 /uv /usr/local/bin/uv

# cp -L kopiuje plik spod symlinka instalatora; reszta po instalatorze zbędna.
# ponytail: instalator bez przypiętej wersji/sumy; przypiąć przed CI.
RUN curl -fsSL https://claude.ai/install.sh | bash \
 && cp -L /root/.local/bin/claude /usr/local/bin/claude \
 && rm -rf /root/.local /root/.cache

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
