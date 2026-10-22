#!/usr/bin/env bash
# Run a locally built production binary. Customer installations use install.sh.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$root"
source scripts/runtime-common.sh
load_env .env
export TALLY_SECRET_KEY="${TALLY_SECRET_KEY:-$(openssl rand -hex 32)}"
if ! grep -q '^TALLY_SECRET_KEY=' .env 2>/dev/null; then (umask 077; write_env TALLY_SECRET_KEY >> .env); fi
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
export TALLY_DATA_DIR="${TALLY_DATA_DIR:-$root/.local/data}"
export TALLY_URL="${TALLY_URL:-https://localhost:2357}"
export TALLY_HTTP_BIND="${TALLY_HTTP_BIND:-127.0.0.1:2357}"
export TALLY_UPGRADE_STATE_DIR="$root/.local/upgrade" TALLY_UPGRADE_WEB_ORIGIN="$TALLY_URL"
export TALLY_MAINTENANCE_DIR="$root/.local/tally-maintenance"
export TALLY_UPGRADE_TALLY_ROOT="$root" TALLY_RUNTIME_MODE=combined
[ ! -f "$TALLY_MAINTENANCE_DIR/retired" ] || { printf 'Tally has been retired after upgrading to Gate.\n'; exit 0; }
binary="${TALLY_BINARY:-$root/target/release/tallyd}"
[ -x "$binary" ] || fail 'Build the production binary first: make build'
"$binary" --check-ui
bash scripts/data-services.sh up
bash scripts/ensure-tally-tls.sh
export TALLY_TLS_CERT_FILE="${TALLY_TLS_CERT_FILE:-$root/.local/tls/tally.crt}"
export TALLY_TLS_KEY_FILE="${TALLY_TLS_KEY_FILE:-$root/.local/tls/tally.key}"
exec "$binary"
