#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) exit 1 ;; esac
binary="${TALLY_RELEASE_BINARY:-$root/target/release/tallyd}"
"$binary" --check-ui
output="${TALLY_RELEASE_OUTPUT_DIR:-$root/dist}"
mkdir -p "$output"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$binary" "$stage/tallyd"
cp LICENSE README.md "$stage/"
mkdir "$stage/scripts"
for helper in install-runtime.sh runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do cp "scripts/$helper" "$stage/scripts/"; done
asset="tallyd-$os-$arch.tar.gz"
tar -czf "$output/$asset" -C "$stage" tallyd scripts LICENSE README.md
(cd "$output"; if command -v sha256sum >/dev/null; then sha256sum "$asset"; else shasum -a 256 "$asset"; fi) > "$output/$asset.sha256"
printf 'Created %s/%s\n' "$output" "$asset"
