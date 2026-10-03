#!/usr/bin/env bash
# Run the coding agent inside the sandbox (ADR-0001).
#   src/guard/sandbox/run.sh            # claude, interactive
#   src/guard/sandbox/run.sh selftest   # attack tests + full suite, inside the box
#   src/guard/sandbox/run.sh login      # one-time Claude login (opens auth domains)
#   src/guard/sandbox/run.sh exec CMD   # any command inside the box
set -euo pipefail
REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
IMAGE=guard-sandbox
PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"   # credential helper
DGX=100.117.237.101:8006                      # vLLM for PII NER (tailnet)
HOSTS=(api.anthropic.com)
[ "${1:-}" = login ] && HOSTS+=(claude.ai console.anthropic.com platform.claude.com)

ctx=$(mktemp -d); trap 'rm -rf "$ctx"' EXIT   # build context: never the repo (.env stays out)
cp "$REPO"/pyproject.toml "$REPO"/uv.lock "$REPO"/src/guard/sandbox/{Dockerfile,entrypoint.sh} "$ctx"
docker build -q -t "$IMAGE" "$ctx" >/dev/null

allow=("$DGX") add_host=()
for h in "${HOSTS[@]}"; do                    # resolve on the host; no DNS inside the box
  for ip in $(python3 -c "import socket,sys;print(*sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET)}))" "$h"); do
    allow+=("$ip:443"); add_host+=(--add-host "$h:$ip")
  done
done

case "${1:-}" in
  selftest) cmd=(uv run pytest -q -p no:cacheprovider tests) ;;
  exec)     shift; cmd=("$@") ;;                 # e.g. run.sh exec claude --version
  login)    cmd=(claude /login) ;;
  *)        cmd=(claude "$@") ;;
esac

tty=(); [ -t 0 ] && [ -t 1 ] && tty=(-it)
exec docker run --rm "${tty[@]}" \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
  --cap-add SETUID --cap-add SETGID --cap-add CHOWN --cap-add SETPCAP \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp --tmpfs /run --tmpfs /home/agent \
  --pids-limit 512 --memory 4g --cpus 4 \
  -e AGENT_UID="$(id -u)" -e AGENT_GID="$(id -g)" -e ALLOW="${allow[*]}" \
  "${add_host[@]}" \
  -v "$REPO":/repo \
  -v "$REPO"/.git:/repo/.git:ro \
  -v "$REPO"/.claude:/repo/.claude:ro \
  -v "$REPO"/src/guard:/repo/src/guard:ro \
  -v /dev/null:/repo/.env:ro \
  --tmpfs /repo/.venv \
  -v guard-claude-home:/home/agent/.claude \
  "$IMAGE" "${cmd[@]}"
