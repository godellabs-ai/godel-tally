#!/usr/bin/env bash
# Fixed-purpose executor. It inherits this installation's mounts and survives tallyd retirement.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "${TALLY_UPGRADE_CONTAINER_EXECUTION:-0}" != 1 ] || [ "${TALLY_UPGRADE_EXECUTOR:-0}" = 1 ]; then
    exec bash "$root/scripts/upgrade-tally-to-gate.sh" "$@"
fi
export DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
source_id="${TALLY_UPGRADE_SOURCE_CONTAINER:-${HOSTNAME:-}}"
[[ "$source_id" =~ ^[a-zA-Z0-9_.-]+$ ]] || { echo 'Cannot identify the source Tally container.' >&2; exit 1; }
source_id="$(docker inspect --format '{{.Id}}' "$source_id")"
image="$(docker inspect --format '{{.Image}}' "$source_id")"
network="$(docker inspect --format '{{range $name, $value := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$source_id" | head -n 1)"
[ -n "$network" ] || { echo 'The source Tally container has no usable Docker network.' >&2; exit 1; }
state="${TALLY_UPGRADE_STATE_DIR:?Upgrade state directory must be configured}"
mkdir -p "$state"
chmod 700 "$state"
executor_env="$(mktemp "$state/executor-env.XXXXXX")"
chmod 600 "$executor_env"
trap 'rm -f "$executor_env"' EXIT
export TALLY_UPGRADE_SOURCE_CONTAINER="$source_id" TALLY_UPGRADE_EXECUTOR=1 TALLY_RUNTIME_MODE=combined-compose TALLY_POSTGRES_MODE=existing
export TALLY_BINARY=/usr/local/bin/tallyd TALLY_UPGRADE_EXECUTOR_ENV_FILE="$executor_env"
# Resolve the source database before attaching Gate's network, where another postgres alias exists.
python3 - "$executor_env" <<'PY'
import os, socket, sys, urllib.parse
values = {k:v for k,v in os.environ.items() if k.startswith('TALLY_') or k in ('DOCKER_HOST','SSL_CERT_FILE','NO_PROXY','no_proxy')}
url = values.get('TALLY_POSTGRES_URL')
if url:
    parsed=urllib.parse.urlsplit(url)
    address=socket.getaddrinfo(parsed.hostname, parsed.port or 5432, type=socket.SOCK_STREAM)[0][4][0]
    authority=parsed.netloc.rsplit('@',1)
    address=f'[{address}]' if ':' in address else address
    host=f'{address}:{parsed.port or 5432}'
    values['TALLY_POSTGRES_URL']=urllib.parse.urlunsplit(parsed._replace(netloc=(authority[0]+'@' if len(authority)==2 else '')+host))
with open(sys.argv[1],'w') as output:
    for key,value in values.items():
        if '\n' in value or '\r' in value: raise SystemExit('Upgrade settings cannot contain newlines')
        output.write(f'{key}={value}\n')
PY
name="tally-upgrade-${source_id:0:12}-${1:-action}"
socket="${DOCKER_HOST#unix://}"
[ "$socket" != "${DOCKER_HOST:-}" ] && [ -S "$socket" ] || { echo 'A configured local Docker socket is required.' >&2; exit 1; }
group="$(stat -c '%g' "$socket")"
mkdir -p "$state/gate-upgrade"
printf '%s' "$name" > "$state/gate-upgrade/executor-container"
# Env values are read by the CLI from a private file, never interpolated into command arguments.
# Output is written by the helper directly to shared durable storage, independent of this client.
docker run --rm --sig-proxy=false --name "$name" --network "$network" --volumes-from "$source_id" \
    --user "$(id -u):$(id -g)" --group-add "$group" --no-healthcheck --env-file "$executor_env" \
    --entrypoint /bin/bash "$image" -c \
    'rm -f -- "$TALLY_UPGRADE_EXECUTOR_ENV_FILE"; phase="$1"; shift; mkdir -p "$TALLY_UPGRADE_STATE_DIR/gate-upgrade"; exec >> "$TALLY_UPGRADE_STATE_DIR/gate-upgrade/$phase.log" 2>&1; bash /opt/tally/scripts/upgrade-tally-to-gate.sh "$phase" "$@"; result=$?; printf "%s" "$result" > "$TALLY_UPGRADE_STATE_DIR/gate-upgrade/$phase-exit"; exit "$result"' \
    executor "$@"
