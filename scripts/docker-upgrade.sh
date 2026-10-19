#!/usr/bin/env bash
# Run from the Docker host, never from the application container.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$root/scripts/runtime-common.sh"
load_env "$root/.env"
export TALLY_UPGRADE_TALLY_ROOT="$root" TALLY_RUNTIME_MODE=combined-compose
export TALLY_UPGRADE_STATE_DIR="$root/.local/docker-state/upgrade"
export TALLY_MAINTENANCE_DIR="$root/.local/docker-state/maintenance"
if [ -n "${TALLY_POSTGRES_URL:-}" ]; then export TALLY_POSTGRES_MODE=existing; fi
export TALLY_URL="${TALLY_URL:-https://localhost:8443}"
export TALLY_BINARY="${TALLY_BINARY:-$root/target/release/tallyd}"
exec bash "$root/scripts/upgrade-tally-to-gate.sh" "$@"
