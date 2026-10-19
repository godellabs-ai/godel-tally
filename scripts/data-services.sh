#!/usr/bin/env bash
# Database lifecycle shared by native production and live-reload development.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/runtime-common.sh"
load_env "${TALLY_ENV_FILE:-$script_dir/../.env}"
export TALLY_DATA_DIR="${TALLY_DATA_DIR:-$script_dir/../.local/data}"
export TALLY_POSTGRES_MODE="${TALLY_POSTGRES_MODE:-${TALLY_DB_MODE:-docker}}"
export TALLY_CLICKHOUSE_MODE="${TALLY_CLICKHOUSE_MODE:-${TALLY_DB_MODE:-docker}}"
prefix="${TALLY_CONTAINER_PREFIX:-godel-tally-dev}"
[[ "$prefix" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail 'Invalid TALLY_CONTAINER_PREFIX'
action="${1:-up}"
case "$action" in up|stop|reset) ;; *) fail 'Usage: data-services.sh up|stop|reset' ;; esac
if [ "$action" = reset ]; then
    for mode in "$TALLY_POSTGRES_MODE" "$TALLY_CLICKHOUSE_MODE"; do
        case "$mode" in docker|apple) ;; *) fail 'Reset requires both databases to use managed containers' ;; esac
    done
fi
mkdir -p "$TALLY_DATA_DIR/containers"
chmod 700 "$TALLY_DATA_DIR" "$TALLY_DATA_DIR/containers"
for db in postgres clickhouse; do
    if [ "$db" = postgres ]; then mode="$TALLY_POSTGRES_MODE"; else mode="$TALLY_CLICKHOUSE_MODE"; fi
    case "$mode" in
        existing) [ "$action" != reset ] || fail 'Reset is supported only for managed containers'; continue ;;
        native)
            [ "$action" != reset ] || fail 'Reset is supported only for managed containers'
            [ "$action" != up ] || start_service "$db"
            # Native databases belong to persistent user services; dev cleanup never stops them.
            continue ;;
        docker) engine=docker; command -v docker >/dev/null || fail 'Install Docker or select native/existing databases' ;;
        apple)
            [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || fail 'Apple container requires an Apple silicon Mac'
            [ "$(sw_vers -productVersion | cut -d. -f1)" -ge 26 ] || fail 'Apple container requires macOS 26 or newer'
            command -v container >/dev/null || fail 'Install https://github.com/apple/container first'
            engine=container
            [ "$action" != up ] || container system start
            ;;
        *) fail "Unknown database mode: $mode" ;;
    esac
    name="$prefix-$db"
    marker="$TALLY_DATA_DIR/containers/$engine-$name"
    if [ "$action" = reset ]; then
        if "$engine" inspect "$name" >/dev/null 2>&1; then
            [ -f "$marker" ] || fail "Refusing to reset container $name owned outside this installation"
            "$engine" stop "$name"
            if [ "$engine" = docker ]; then "$engine" rm "$name"; else "$engine" delete "$name"; fi
        fi
        if [ "$db" = postgres ]; then volume="${TALLY_POSTGRES_VOLUME:-$prefix-postgres}"
        else volume="${TALLY_CLICKHOUSE_VOLUME:-$prefix-clickhouse}"; fi
        if "$engine" volume inspect "$volume" >/dev/null 2>&1; then
            "$engine" volume rm "$volume"
        fi
        rm -f "$marker"
        continue
    fi
    if [ "$action" = stop ]; then
        [ ! -f "$marker" ] || "$engine" stop "$name"
        continue
    fi
    if "$engine" inspect "$name" >/dev/null 2>&1; then
        [ -f "$marker" ] || fail "Container $name already exists outside this installation; choose another TALLY_CONTAINER_PREFIX"
        if [ "$engine" = docker ]; then
            running="$(docker inspect --format '{{.State.Running}}' "$name")"
            [ "$running" = true ] || docker start "$name"
        elif ! container ls --quiet | grep -Fxq "$name"; then
            "$engine" start "$name"
        fi
    else
        if [ "$db" = postgres ]; then
            image="${TALLY_POSTGRES_IMAGE:-postgres:18-alpine}"
            volume="${TALLY_POSTGRES_VOLUME:-$prefix-postgres}"
            port="${TALLY_POSTGRES_PORT:-5433}:5432"; mount=/var/lib/postgresql
        else
            image="${TALLY_CLICKHOUSE_IMAGE:-clickhouse:26.9}"
            volume="${TALLY_CLICKHOUSE_VOLUME:-$prefix-clickhouse}"
            port="${TALLY_CLICKHOUSE_PORT:-8124}:8123"; mount=/var/lib/clickhouse
        fi
        "$engine" volume inspect "$volume" >/dev/null 2>&1 || "$engine" volume create "$volume" >/dev/null
        credentials="$(mktemp "$TALLY_DATA_DIR/containers/.env.XXXXXX")"
        chmod 600 "$credentials"
        trap 'rm -f "${credentials:-}"' EXIT
        if [ "$db" = postgres ]; then
            printf 'POSTGRES_USER=tally\nPOSTGRES_DB=tally\nPOSTGRES_PASSWORD=%s\n' "${TALLY_POSTGRES_PASSWORD:-tally}" > "$credentials"
        else
            printf 'CLICKHOUSE_USER=tally\nCLICKHOUSE_DB=tally\nCLICKHOUSE_PASSWORD=%s\nCLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1\n' "${TALLY_CLICKHOUSE_PASSWORD:-tally-local}" > "$credentials"
        fi
        options=()
        if [ "$engine" = docker ]; then options+=(--restart unless-stopped); else options+=(--memory 2G --cpus 2); fi
        "$engine" run -d --name "$name" "${options[@]}" --env-file "$credentials" -p "127.0.0.1:$port" -v "$volume:$mount" "$image" >/dev/null
        rm -f "$credentials"
        : > "$marker"
    fi
    ready=0
    for attempt in $(seq 1 90); do
        if [ "$db" = postgres ]; then
            if "$engine" exec "$name" pg_isready -h 127.0.0.1 -U tally -d tally >/dev/null 2>&1; then ready=1; break; fi
        elif "$engine" exec "$name" sh -c 'test "$(cat /proc/1/comm)" = clickhouse-serv && clickhouse-client --user tally --password "$CLICKHOUSE_PASSWORD" --query "SELECT 1"' >/dev/null 2>&1; then ready=1; break; fi
        sleep 1
    done
    [ "$ready" = 1 ] || fail "$db did not become ready; inspect $engine logs $name"
done
