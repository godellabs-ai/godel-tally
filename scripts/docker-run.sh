#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
source scripts/runtime-common.sh
load_env .env
umask 077
for key in TALLY_SECRET_KEY TALLY_POSTGRES_PASSWORD TALLY_CLICKHOUSE_PASSWORD; do
    if [ -z "${!key:-}" ]; then
        export "$key=$(openssl rand -hex 32)"
        write_env "$key" >> .env
    fi
done
export TALLY_UID="$(id -u)" TALLY_GID="$(id -g)"
if ! grep -q '^TALLY_UID=' .env; then write_env TALLY_UID TALLY_GID >> .env; fi
mkdir -p .local/docker-state
chmod 700 .local/docker-state
export TALLY_URL="${TALLY_URL:-https://localhost:8443}"
bash scripts/ensure-tally-tls.sh
# Non-root app container reads copies; never change permissions of supplied private keys.
mkdir -p .local/docker-tls
chmod 700 .local/docker-tls
cp "${TALLY_TLS_CERT_FILE:-.local/tls/tally.crt}" .local/docker-tls/tally.crt
cp "${TALLY_TLS_KEY_FILE:-.local/tls/tally.key}" .local/docker-tls/tally.key
chmod 644 .local/docker-tls/tally.crt .local/docker-tls/tally.key
export TALLY_TLS_DIR="$root/.local/docker-tls"
exec docker compose -f docker-compose.yml -f docker-compose.build.yml up --build -d
