#!/usr/bin/env bash
# Run Tally, PostgreSQL, and ClickHouse with Apple container, using the same images and .env as the
# Docker Compose deployment. Apple container has no Compose or restart policy: rerun `up` after a
# restart. Run from the directory that contains .env:
#   bash tally-container.sh up|stop|status|logs|remove
set -euo pipefail
prefix=godel-tally-stack
fail() { printf 'Tally: %s\n' "$*" >&2; exit 1; }
action="${1:-}"
case "$action" in up|stop|status|logs|remove) ;; *) fail 'Usage: bash tally-container.sh up|stop|status|logs|remove' ;; esac
[ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || fail 'Apple container requires an Apple silicon Mac'
[ "$(sw_vers -productVersion | cut -d. -f1)" -ge 26 ] || fail 'Apple container requires macOS 26 or newer'
command -v container >/dev/null || fail 'Install Apple container from https://github.com/apple/container first'
exists() { container inspect "$1" >/dev/null 2>&1; }
running() { container ls --quiet | grep -Fxq "$1"; }

case "$action" in
    stop)
        for name in tallyd clickhouse postgres; do if running "$prefix-$name"; then container stop "$prefix-$name" >/dev/null; fi; done
        echo 'Tally stopped. Data volumes are retained.'
        exit 0 ;;
    remove)
        for name in tallyd clickhouse postgres; do
            if exists "$prefix-$name"; then container stop "$prefix-$name" >/dev/null 2>&1 || true; container delete "$prefix-$name" >/dev/null; fi
        done
        echo "Containers removed. Data volumes are retained; delete them with:"
        echo "  container volume rm $prefix-postgres $prefix-clickhouse $prefix-data"
        exit 0 ;;
    status) container ls --all | grep -E "^(ID|$prefix-)" || true; exit 0 ;;
    logs) exec container logs "$prefix-tallyd" ;;
esac

[ -f .env ] || fail 'Create .env in this directory first (see the Apple container installation guide)'
# Same KEY=value format as Docker Compose .env; values are data, never shell code.
declare -a settings=()
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue ;; esac
    key="${line%%=*}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && [ "$key" != "$line" ] || fail "Expected KEY=value in .env: $key"
    settings+=("$line")
    printf -v "env_$key" '%s' "${line#*=}"
done < .env
setting() { local name="env_$1"; printf '%s' "${!name:-${2:-}}"; }
for key in TALLY_SECRET_KEY TALLY_POSTGRES_PASSWORD TALLY_CLICKHOUSE_PASSWORD; do
    [ -n "$(setting "$key")" ] || fail "Set $key in .env"
done
url="$(setting TALLY_URL https://localhost:2357)"
publish="$(setting TALLY_PUBLISH_BIND 127.0.0.1:2357)"
image="$(setting TALLY_IMAGE_PREFIX quay.io/godellabs-ai)/godel-tally:$(setting TALLY_IMAGE_TAG 0.1.4)"
tls_dir="$(setting TALLY_TLS_DIR ./tls)"
mkdir -p "$tls_dir"
tls_dir="$(cd "$tls_dir" && pwd)"

container system start
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
chmod 700 "$work"
for volume in postgres clickhouse data; do
    container volume inspect "$prefix-$volume" >/dev/null 2>&1 || container volume create "$prefix-$volume" >/dev/null
done
for db in postgres clickhouse; do
    name="$prefix-$db"
    if exists "$name"; then
        running "$name" || container start "$name" >/dev/null
        continue
    fi
    if [ "$db" = postgres ]; then
        printf 'POSTGRES_USER=tally\nPOSTGRES_DB=tally\nPOSTGRES_PASSWORD=%s\n' "$(setting TALLY_POSTGRES_PASSWORD)" > "$work/$db.env"
        container run -d --name "$name" --memory 2G --cpus 2 --env-file "$work/$db.env" \
            -v "$prefix-postgres:/var/lib/postgresql" postgres:18-alpine >/dev/null
    else
        printf 'CLICKHOUSE_USER=tally\nCLICKHOUSE_DB=tally\nCLICKHOUSE_PASSWORD=%s\nCLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1\n' \
            "$(setting TALLY_CLICKHOUSE_PASSWORD)" > "$work/$db.env"
        container run -d --name "$name" --memory 2G --cpus 2 --env-file "$work/$db.env" \
            -v "$prefix-clickhouse:/var/lib/clickhouse" clickhouse:26.9 >/dev/null
    fi
done
wait_for() {
    local name="$1" attempt
    shift
    for attempt in $(seq 1 120); do
        if container exec "$name" "$@" >"$work/readiness.log" 2>&1; then return 0; fi
        sleep 1
    done
    cat "$work/readiness.log" >&2
    fail "$name did not become ready; inspect: container logs $name"
}
wait_for "$prefix-postgres" sh -c 'pg_isready -h 127.0.0.1 -U tally -d tally'
wait_for "$prefix-clickhouse" sh -c 'test "$(cat /proc/1/comm)" = clickhouse-serv && clickhouse-client --user tally --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"'
# Containers reach each other by address; addresses can change when a database restarts.
address() {
    local ip
    ip="$(container inspect "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -1 | cut -d/ -f1)"
    [ -n "$ip" ] || fail "Could not find the network address of $1"
    printf '%s' "$ip"
}
postgres_ip="$(address "$prefix-postgres")"
clickhouse_ip="$(address "$prefix-clickhouse")"

managed='TALLY_CLICKHOUSE_URL TALLY_CLICKHOUSE_DATABASE TALLY_HTTP_BIND TALLY_POSTGRES_URL TALLY_LOG TALLY_LOG_FORMAT TALLY_URL TALLY_MAINTENANCE_DIR TALLY_UPGRADE_HOST_REQUIRED TALLY_UPGRADE_STATE_DIR TALLY_UPGRADE_WEB_ORIGIN TALLY_AI_LOG_RETENTION_DAYS'
{
    for line in ${settings[@]+"${settings[@]}"}; do
        case " $managed " in *" ${line%%=*} "*) ;; *) printf '%s\n' "$line" ;; esac
    done
    printf 'TALLY_CLICKHOUSE_URL=http://%s:8123?user=tally\n' "$clickhouse_ip"
    printf 'TALLY_CLICKHOUSE_DATABASE=tally\n'
    # Generated passwords are hexadecimal. URL-encode manually supplied PostgreSQL passwords.
    printf 'TALLY_POSTGRES_URL=%s\n' "$(setting TALLY_POSTGRES_URL "postgres://tally:$(setting TALLY_POSTGRES_PASSWORD)@$postgres_ip:5432/tally")"
    printf 'TALLY_AI_LOG_RETENTION_DAYS=%s\n' "$(setting TALLY_AI_LOG_RETENTION_DAYS 90)"
    printf 'TALLY_HTTP_BIND=0.0.0.0:2357\nTALLY_LOG=info,tower_http=info\nTALLY_LOG_FORMAT=json\n'
    printf 'TALLY_URL=%s\nTALLY_UPGRADE_WEB_ORIGIN=%s\n' "$url" "$url"
    printf 'TALLY_MAINTENANCE_DIR=/data/maintenance\nTALLY_UPGRADE_HOST_REQUIRED=1\nTALLY_UPGRADE_STATE_DIR=/data/upgrade\n'
} > "$work/tallyd.env"
# Recreate the application each time so it receives the current database addresses.
if exists "$prefix-tallyd"; then container stop "$prefix-tallyd" >/dev/null 2>&1 || true; container delete "$prefix-tallyd" >/dev/null; fi
container run -d --name "$prefix-tallyd" --env-file "$work/tallyd.env" -p "$publish:2357" \
    -v "$prefix-data:/data" -v "$tls_dir:/tls" "$image" >/dev/null
wait_for "$prefix-tallyd" /usr/local/bin/tallyd healthcheck
echo "Tally is ready at $url"
