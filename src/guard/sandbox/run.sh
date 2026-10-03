#!/usr/bin/env bash
# Run the coding agent inside the sandbox (ADR-0001).
#   src/guard/sandbox/run.sh            # claude, interactive
#   src/guard/sandbox/run.sh selftest   # attack tests + full suite, inside the box
#   src/guard/sandbox/run.sh login      # one-time Claude login (opens auth domains)
#   src/guard/sandbox/run.sh exec CMD   # any command inside the box

# -e: stop przy 1. błędzie · -u: nieustawiona zmienna = błąd · -o pipefail: a|b pada, gdy pada którykolwiek
set -euo pipefail
# $0 = ścieżka skryptu → dirname = jego katalog → git -C KAT = odpal git stamtąd → korzeń repo z dowolnego cwd
REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
IMAGE=guard-sandbox                           # nazwa (tag) obrazu
# macOS: helper haseł Docker Desktop bywa poza PATH; na Linux/WSL katalogu brak = zero efektu
PATH="$PATH:/Applications/Docker.app/Contents/Resources/bin"
DGX=100.117.237.101:8006                      # vLLM do NER PII (tailnet), ip:port
HOSTS=(api.anthropic.com)                     # domeny, do których agent może się łączyć
# ${1:-} = 1. argument albo "" (bez tego set -u wywala przy braku argumentów) · A && B = B tylko gdy A prawdziwe
[ "${1:-}" = login ] && HOSTS+=(claude.ai console.anthropic.com platform.claude.com)

# mktemp -d = nowy, unikalny, pusty katalog tymczasowy · trap '…' EXIT = sprzątnij przy wyjściu, też po błędzie
ctx=$(mktemp -d); trap 'rm -rf "$ctx"' EXIT   # kontekst buildu: nigdy całe repo (.env zostaje poza obrazem)
# {a,b} = rozwinięcie nawiasów → …/Dockerfile …/entrypoint.sh
cp "$REPO"/pyproject.toml "$REPO"/uv.lock "$REPO"/src/guard/sandbox/{Dockerfile,entrypoint.sh} "$ctx"
# -q: cicho, wypisz tylko ID obrazu · -t: nadaj nazwę · >/dev/null: wyrzuć ID (stdout); błędy (stderr) dalej widać
docker build -q -t "$IMAGE" "$ctx" >/dev/null
rm -rf "$ctx"                                 # od razu: exec na dole podmienia proces, więc trap EXIT już nie odpali

allow=("$DGX") add_host=()                    # allow = ip:port dla firewalla · add_host = flagi --add-host dla dockera
for h in "${HOSTS[@]}"; do                    # "${a[@]}" = każdy element osobno · DNS robimy tu, bo w pudle jest zablokowany
  # getaddrinfo → krotki (rodzina, typ, proto, nazwa, adres); a[4] = adres = (ip, port) → a[4][0] = samo ip
  # AF_INET = tylko IPv4 (IPv6 w pudle i tak zamknięte) · {…} = zbiór bez duplikatów · print(*x) = elementy po spacji
  for ip in $(python3 -c "import socket,sys;print(*sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1],443,socket.AF_INET)}))" "$h"); do
    allow+=("$ip:443"); add_host+=(--add-host "$h:$ip")   # firewall wpuści ip:443 · docker wpisze "ip domena" do /etc/hosts
  done
done

# case = switch · ;; = koniec gałęzi · esac = "case" wspak · * = wszystko inne
case "${1:-}" in
  selftest) cmd=(uv run pytest -q -p no:cacheprovider tests) ;;   # no:cacheprovider = bez .pytest_cache
  exec)     shift; cmd=("$@") ;;              # shift = wyrzuć 1. arg, "$@" = reszta · np. run.sh exec claude --version
  login)    cmd=(claude /login) ;;
  *)        cmd=(claude "$@") ;;              # domyślnie wszystkie argumenty idą do claude
esac

# .guard is read-only for the agent (consent, vault); only the audit file is writable (R2: still tamperable)
# [ -L x ] = x to symlink → odmowa (symlink mógłby przekierować montowanie gdzie indziej) · >&2 = na stderr
g="$REPO/.guard"; [ -L "$g" ] && { echo "refusing symlinked .guard" >&2; exit 1; }
mkdir -p "$g"; [ -L "$g/audit.jsonl" ] && { echo "refusing symlinked audit.jsonl" >&2; exit 1; }
touch "$g/audit.jsonl"                        # plik musi istnieć, inaczej docker zamontuje w jego miejscu katalog
audit_env=(-e GUARD_AUDIT_PATH=/var/log/guard-audit.jsonl); [ "${1:-}" = selftest ] && audit_env=()  # tests use temp repos

mask=()   # existing secret-looking files read as empty and stay read-only; absent ones get no stub
# find -print0 + read -d '' = nazwy rozdzielone bajtem \0 (bezpieczne dla spacji) · ${f#"$REPO"/} = ścieżka względna
# < <(…) = wynik komendy jako wejście pętli; pętla zostaje w tym shellu, więc mask+= przeżywa
while IFS= read -r -d '' f; do mask+=(-v "/dev/null:/repo/${f#"$REPO"/}:ro"); done < <(
  find "$REPO" -maxdepth 2 \( -name .env -o -name '.env.*' -o -name secrets.env -o -name '*.pem' -o -name '*.key' \) \
    -type f -not -path '*/.git/*' -not -path '*/.venv/*' -not -path '*/node_modules/*' -print0)

# [ -t 0 ] / [ -t 1 ] = stdin / stdout to terminal → -it (interaktywnie); w CI i w rurze bez tego
tty=(); [ -t 0 ] && [ -t 1 ] && tty=(-it)
# ${a[@]+"${a[@]}"} = rozwiń tylko gdy niepusta; bash 3.2 (macOS bez brew) przy set -u wywala się na pustej tablicy
args=(
  --rm                                        # usuń kontener po wyjściu
  ${tty[@]+"${tty[@]}"}
  --cap-drop ALL                              # zabierz rootowi wszystkie uprawnienia jądra, oddaj tylko te dla entrypointa:
  --cap-add NET_ADMIN --cap-add NET_RAW       #   iptables (firewall)
  --cap-add SETUID --cap-add SETGID           #   setpriv: przejście na uid/gid agenta
  --cap-add CHOWN                             #   chown /home/agent
  --cap-add SETPCAP                           #   setpriv: kasuje resztę uprawnień → agent startuje z zerem
  --security-opt no-new-privileges            # żaden exec (np. plik setuid) nie podniesie uprawnień
  --read-only                                 # system plików obrazu tylko do odczytu
  --tmpfs /tmp --tmpfs /run --tmpfs /home/agent   # zapisywalne katalogi w RAM, znikają z kontenerem
  --pids-limit 512 --memory 4g --cpus 4       # limity: fork-bomba, RAM, CPU
  -e AGENT_UID="$(id -u)" -e AGENT_GID="$(id -g)"   # agent = twój uid → pliki w repo należą do ciebie, nie do roota
  -e ALLOW="${allow[*]}"                      # [*] = elementy sklejone spacją w jeden string
  ${add_host[@]+"${add_host[@]}"}
  -v "$REPO":/repo                            # repo do zapisu (agent pracuje na kodzie)…
  -v "$REPO"/.git:/repo/.git:ro               # …ale historia git,
  -v "$REPO"/.claude:/repo/.claude:ro         #    ustawienia Claude
  -v "$REPO"/src/guard:/repo/src/guard:ro     #    i sam strażnik tylko do odczytu (agent go nie wyłączy)
  -v "$g":/repo/.guard:ro
  -v "$g/audit.jsonl":/var/log/guard-audit.jsonl   # jedyny zapisywalny plik strażnika: log audytu
  ${audit_env[@]+"${audit_env[@]}"}
  ${mask[@]+"${mask[@]}"}                     # sekrety przykryte pustym /dev/null
  --tmpfs /repo/.venv                         # przykrywa venv hosta (macOS ≠ Linux); właściwy jest w /opt/venv
  -v guard-claude-home:/home/agent/.claude    # nazwany wolumen: login Claude przeżywa restart
)
# exec = zastąp ten skrypt dockerem: Ctrl-C, sygnały i kod wyjścia idą prosto
exec docker run "${args[@]}" "$IMAGE" "${cmd[@]}"
