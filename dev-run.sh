#!/usr/bin/env bash
# Native Rust + Next.js live reload; only the databases use containers by default.
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"
source scripts/runtime-common.sh
source scripts/dev-rust-watch.sh
command -v cargo >/dev/null || fail 'Install Rust first'
command -v npm >/dev/null || fail 'Install Node.js 24 first'
command -v openssl >/dev/null || fail 'OpenSSL is required for local credentials and TLS'
if [ ! -f .env ]; then
    (umask 077; printf 'TALLY_SECRET_KEY=%s\n' "$(openssl rand -hex 32)" > .env)
fi
load_env .env
if [ -z "${TALLY_SECRET_KEY:-}" ]; then
    export TALLY_SECRET_KEY="$(openssl rand -hex 32)"
    (umask 077; write_env TALLY_SECRET_KEY >> .env)
fi
export TALLY_RUNTIME_MODE=combined-dev
export TALLY_CONTAINER_PREFIX="${TALLY_CONTAINER_PREFIX:-godel-tally-dev}"
export TALLY_DB_MODE="${TALLY_DB_MODE:-docker}"
export TALLY_POSTGRES_MODE="${TALLY_POSTGRES_MODE:-$TALLY_DB_MODE}"
export TALLY_CLICKHOUSE_MODE="${TALLY_CLICKHOUSE_MODE:-$TALLY_DB_MODE}"
if [ "$TALLY_POSTGRES_MODE" = existing ]; then
    [ -n "${TALLY_POSTGRES_URL:-}" ] || fail 'Existing PostgreSQL requires TALLY_POSTGRES_URL'
else
    export TALLY_POSTGRES_URL="${TALLY_POSTGRES_URL:-postgres://tally:${TALLY_POSTGRES_PASSWORD:-tally}@127.0.0.1:${TALLY_POSTGRES_PORT:-5433}/tally}"
fi
if [ "$TALLY_CLICKHOUSE_MODE" = existing ]; then
    [ -n "${TALLY_CLICKHOUSE_URL:-}" ] || fail 'Existing ClickHouse requires TALLY_CLICKHOUSE_URL'
else
    export TALLY_CLICKHOUSE_URL="${TALLY_CLICKHOUSE_URL:-http://127.0.0.1:${TALLY_CLICKHOUSE_PORT:-8124}?user=tally}"
    export TALLY_CLICKHOUSE_PASSWORD="${TALLY_CLICKHOUSE_PASSWORD:-tally-local}"
fi
export TALLY_DATA_DIR="${TALLY_DATA_DIR:-$REPO_DIR/.local/data}"
export TALLY_DEV_BIND="${TALLY_DEV_BIND:-127.0.0.1:8080}"
export TALLY_WEB_HOST="${TALLY_DEV_BIND%:*}" TALLY_WEB_PORT="${TALLY_DEV_BIND##*:}"
[[ "$TALLY_WEB_PORT" =~ ^[0-9]+$ ]] && [ "$TALLY_WEB_PORT" -ge 1 ] && [ "$TALLY_WEB_PORT" -le 65535 ] || fail 'Invalid TALLY_DEV_BIND port'
export TALLY_URL="${TALLY_URL:-https://localhost:$TALLY_WEB_PORT}"
export TALLY_HTTP_BIND="${TALLY_HTTP_BIND:-127.0.0.1:8788}"
export TALLY_CLICKHOUSE_DATABASE="${TALLY_CLICKHOUSE_DATABASE:-tally}"
export TALLY_API_INTERNAL_URL="http://127.0.0.1:${TALLY_HTTP_BIND##*:}/api/v1/tally"
export TALLY_AUTH_INTERNAL_URL="http://127.0.0.1:${TALLY_HTTP_BIND##*:}/api/v1/auth"
export TALLY_UPGRADE_STATE_DIR="$REPO_DIR/.local/upgrade" TALLY_UPGRADE_WEB_ORIGIN="$TALLY_URL"
export TALLY_UPGRADE_TALLY_ROOT="$REPO_DIR" TALLY_MAINTENANCE_DIR="$REPO_DIR/.local/tally-maintenance"
[ ! -f "$TALLY_MAINTENANCE_DIR/retired" ] || { printf 'Tally has been retired after upgrading to Gate.\n'; exit 0; }
unset NEXT_PUBLIC_TALLY_API_URL
# Reuse the existing local Docker data volumes for upgrades from the old dev stack.
export TALLY_POSTGRES_VOLUME="${TALLY_POSTGRES_VOLUME:-godel-tally_tally-postgres}"
export TALLY_CLICKHOUSE_VOLUME="${TALLY_CLICKHOUSE_VOLUME:-godel-tally_tally-clickhouse}"

if ! cargo watch --version >/dev/null 2>&1; then cargo install cargo-watch --locked; fi
# Build before launching any watchers, readiness timers or databases.
cargo build -p tallyd --bin tallyd
[ -d apps/web/node_modules ] || npm --prefix apps/web ci
bash scripts/ensure-tally-tls.sh
cert="${TALLY_TLS_CERT_FILE:-$REPO_DIR/.local/tls/tally.crt}"
key="${TALLY_TLS_KEY_FILE:-$REPO_DIR/.local/tls/tally.key}"
if [ "${TALLY_RESET_DB:-0}" = 1 ]; then bash scripts/data-services.sh reset; fi
bash scripts/data-services.sh up
PIDS=()
kill_tree() {
    local pid="$1" child
    for child in $(pgrep -P "$pid" 2>/dev/null || true); do kill_tree "$child"; done
    kill -TERM "$pid" 2>/dev/null || true
}
cleanup() {
    trap - EXIT INT TERM
    for pid in "${PIDS[@]}"; do kill_tree "$pid"; done
    for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -f "$TALLY_UPGRADE_STATE_DIR/dev-processes"
    if [ "${TALLY_KEEP_DB:-0}" != 1 ]; then bash "$REPO_DIR/scripts/data-services.sh" stop; fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM
# Next.js owns dev TLS; the private Rust listener uses HTTP for its development proxies.
env -u TALLY_TLS_CERT_FILE -u TALLY_TLS_KEY_FILE cargo watch "${TALLY_RUST_WATCH_ARGS[@]}" -x 'run -p tallyd' </dev/null &
PIDS+=("$!")
mkdir -p "$TALLY_UPGRADE_STATE_DIR"
(umask 077; printf 'API_PID=%s\n' "${PIDS[0]}" > "$TALLY_UPGRADE_STATE_DIR/dev-processes")
ready=0
for attempt in $(seq 1 180); do
    if curl -fsS --max-time 2 "$TALLY_API_INTERNAL_URL/health/ready" >/dev/null 2>&1; then ready=1; break; fi
    kill -0 "${PIDS[0]}" 2>/dev/null || fail 'Rust watcher exited before Tally became ready'
    sleep 1
done
[ "$ready" = 1 ] || fail 'Tally did not become ready within 180 seconds'
start_web() {
    npm --prefix apps/web run dev -- --experimental-https --experimental-https-cert "$cert" --experimental-https-key "$key" </dev/null &
    PIDS[1]="$!"
    printf 'API_PID=%s\nWEB_PID=%s\n' "${PIDS[0]}" "${PIDS[1]}" > "$TALLY_UPGRADE_STATE_DIR/dev-processes"
}
start_web
printf 'Gödel Tally dev stack is up: %s\nRust reload: API, connectors and Upgrade. UI: Next.js hot reload. Ctrl-C stops development.\n' "$TALLY_URL"
# Bash 3.2 has no wait -n. Detect either dev process exiting and clean up its sibling.
web_paused=0
while kill -0 "${PIDS[0]}" 2>/dev/null; do
    [ ! -f "$TALLY_MAINTENANCE_DIR/retired" ] || exit 0
    if [ -f "$TALLY_MAINTENANCE_DIR/http-paused" ]; then
        if [ "$web_paused" = 0 ]; then
            kill_tree "${PIDS[1]}"; wait "${PIDS[1]}" 2>/dev/null || true
            web_paused=1
        fi
    elif [ "$web_paused" = 1 ]; then
        start_web; web_paused=0
    else
        kill -0 "${PIDS[1]}" 2>/dev/null || break
    fi
    sleep 1
done
fail 'A development process exited'
