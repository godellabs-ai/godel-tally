#!/usr/bin/env bash
# Download a verified release, then run the bundled installer. No source checkout required.
set -euo pipefail
repo="${TALLY_GITHUB_REPO:-godellabs-ai/godel-tally}"
version="${TALLY_VERSION:-latest}"
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) echo 'Tally supports Linux and macOS.' >&2; exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo 'Tally supports amd64 and arm64.' >&2; exit 1 ;; esac
case "$version" in *[!A-Za-z0-9._-]*|'') echo 'Invalid TALLY_VERSION' >&2; exit 1 ;; esac
case "$repo" in *[!A-Za-z0-9._/-]*|'') echo 'Invalid TALLY_GITHUB_REPO' >&2; exit 1 ;; esac
if [ "${1:-}" = --help ]; then
    cat <<'HELP'
Install Tally: bash install.sh [--db native|docker|apple|existing]
  --postgres MODE       Override PostgreSQL mode independently
  --clickhouse MODE     Override ClickHouse mode independently
  --no-start            Install and register services without starting Tally
  --no-service          Provision databases and install; run Tally manually
  --dry-run             Describe the platform and deployment; make no changes
Environment: TALLY_VERSION (release tag, default latest), TALLY_GITHUB_REPO,
TALLY_INSTALL_DIR, TALLY_DATA_DIR, TALLY_CONFIG_DIR, TALLY_URL,
TALLY_POSTGRES_URL / TALLY_CLICKHOUSE_URL (required for existing mode).
Run as your normal user. Only native Linux package installation uses sudo.
HELP
    exit 0
fi
for arg in "$@"; do
    if [ "$arg" = --dry-run ]; then
        printf 'Platform: %s/%s\nRelease: %s (%s)\nDefault databases: native; overrides: %s\nService: %s\n' "$os" "$arch" "$version" "$repo" "$*" "$( [ "$os" = linux ] && echo 'systemd --user' || echo 'launchd LaunchAgent' )"
        exit 0
    fi
done
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
command -v tar >/dev/null || { echo 'tar is required' >&2; exit 1; }
asset="tallyd-${os}-${arch}.tar.gz"
if [ "$version" = latest ]; then base="https://github.com/$repo/releases/latest/download"
else base="https://github.com/$repo/releases/download/$version"; fi
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
curl --proto '=https' --tlsv1.2 -fLsS --retry 3 "$base/$asset" -o "$stage/$asset"
curl --proto '=https' --tlsv1.2 -fLsS --retry 3 "$base/SHA256SUMS" -o "$stage/SHA256SUMS"
expected="$(awk -v name="$asset" '$2 == name {print $1}' "$stage/SHA256SUMS")"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || { echo 'Release checksum missing or ambiguous' >&2; exit 1; }
if command -v sha256sum >/dev/null; then actual="$(sha256sum "$stage/$asset" | cut -d ' ' -f1)"
else actual="$(shasum -a 256 "$stage/$asset" | cut -d ' ' -f1)"; fi
[ "$actual" = "$expected" ] || { echo 'Release checksum mismatch' >&2; exit 1; }
# These archives are flat and contain only the binary, documentation and installer helpers.
if tar -tzf "$stage/$asset" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then echo 'Unsafe archive paths' >&2; exit 1; fi
tar -xzf "$stage/$asset" -C "$stage"
bash "$stage/scripts/install-runtime.sh" "$stage" "$@"
