# Sandbox agenta (ADR-0001). Kod repo nie jest w obrazie — run.sh montuje go jako /repo.
FROM python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed

# rg = Grep/search_files w agencie; iptables = firewall; curl = diagnostyka. Kasujemy tylko indeks apt.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ripgrep iptables ca-certificates curl bash \
 && rm -rf /var/lib/apt/lists/*

# uv (Astral) = menedżer pakietów Pythona; jeden plik binarny z oficjalnego obrazu.
COPY --from=ghcr.io/astral-sh/uv:0.9.4@sha256:c4089b0085cf4d38e38d5cdaa5e57752c1878a6f41f2e3a3a234dc5f23942cb4 /uv /usr/local/bin/uv

# Hermes Agent: koło z PyPI, wersja i sha256 przypięte w hermes-requirements.txt (razem z
# pełnym drzewem zależności i hashami — pip --require-hashes). Niezgodna suma = build pada.
# Aktualizacja: nowe URL+sha z https://pypi.org/simple/hermes-agent/ i przegenrowany plik.
COPY hermes-requirements.txt /build/hermes-requirements.txt
RUN python3 -m venv /opt/hermes \
 && /opt/hermes/bin/pip install --no-cache-dir --require-hashes -r /build/hermes-requirements.txt \
 && rm -rf /build

# Zależności guarda w buildzie (runtime bez sieci). venv w /opt, bo /repo/.venv to venv hosta (macOS).
# a+rX: odczyt dla wszystkich, wykonanie tylko katalogi i pliki już wykonywalne (agent to uid 501).
COPY pyproject.toml uv.lock /build/
RUN cd /build && UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-install-project --no-cache \
 && chmod -R a+rX /opt/venv /opt/hermes && rm -rf /build

# UV_*: tylko to, co w obrazie (bez sync, locka, sieci). Bez __pycache__ (src/guard jest read-only).
# GUARD_SANDBOX: włącza testy ataku. GUARD_PYTHON/GUARD_CWD: mostek pluginu Hermes -> rdzeń decyzji.
# HERMES_*: plugin projektowy (.hermes/plugins w /repo, montowany przez run.sh) + stan w wolumenie.
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_NO_SYNC=1 UV_FROZEN=1 UV_OFFLINE=1 \
    UV_CACHE_DIR=/tmp/uv-cache PYTHONDONTWRITEBYTECODE=1 \
    GUARD_PYTHON=/opt/venv/bin/python GUARD_CWD=/repo \
    HERMES_HOME=/home/agent/.hermes-home HERMES_ENABLE_PROJECT_PLUGINS=1 \
    PATH=/opt/hermes/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/home/agent GUARD_SANDBOX=1

# Każda komenda idzie przez entrypoint: firewall, potem zrzut do uid agenta bez uprawnień.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
WORKDIR /repo
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["hermes"]