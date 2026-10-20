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
  --port PORT           HTTPS port (default 8443; preserves saved port on reinstall)
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
# Validate options before fetching a release. Keep the original arguments for the runtime.
args=("$@"); dry_run=0; selected_port='8443 (or saved port)'
while [ "$#" -gt 0 ]; do
    case "$1" in
        --port)
            [ "$#" -ge 2 ] && [[ "$2" =~ ^[1-9][0-9]{3,4}$ ]] && [ "$2" -ge 1024 ] && [ "$2" -le 65535 ] || { echo 'Tally: --port must be between 1024 and 65535' >&2; exit 1; }
            selected_port="$2"; shift 2 ;;
        --db|--postgres|--clickhouse)
            [ "$#" -ge 2 ] || { echo "Missing value for $1" >&2; exit 1; }
            case "$2" in native|docker|apple|existing) ;; *) echo "Invalid database mode: $2" >&2; exit 1 ;; esac
            shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        --no-start|--no-service) shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done
if [ "${#args[@]}" -gt 0 ]; then set -- "${args[@]}"; else set --; fi
if [ "$dry_run" = 1 ]; then
    printf 'Platform: %s/%s\nRelease: %s (%s)\nHTTPS port: %s\nDefault databases: native; overrides: %s\nService: %s\n' "$os" "$arch" "$version" "$repo" "$selected_port" "$*" "$( [ "$os" = linux ] && echo 'systemd --user' || echo 'launchd LaunchAgent' )"
    exit 0
fi
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 1; }
command -v tar >/dev/null || { echo 'tar is required' >&2; exit 1; }
printf 'Tally: installing for %s/%s\n' "$os" "$arch"
asset="tallyd-${os}-${arch}.tar.gz"
if [ "$version" = latest ]; then
    printf 'Tally: finding the latest release on GitHub...\n'
    # Resolve once so an update cannot mix an archive and checksums from different releases.
    release_url="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --retry 3 \
        -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")"
    case "$release_url" in
        "https://github.com/$repo/releases/tag/"*) version="${release_url##*/}" ;;
        *) echo 'Could not resolve the latest Tally release' >&2; exit 1 ;;
    esac
    case "$version" in *[!A-Za-z0-9._-]*|'') echo 'Invalid release tag' >&2; exit 1 ;; esac
fi
base="https://github.com/$repo/releases/download/$version"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
printf 'Tally: downloading %s (%s)...\n' "$version" "$asset"
curl --proto '=https' --tlsv1.2 -fL --progress-bar --retry 3 "$base/$asset" -o "$stage/$asset"
printf 'Tally: downloading and verifying the release checksum...\n'
curl --proto '=https' --tlsv1.2 -fLsS --retry 3 "$base/SHA256SUMS" -o "$stage/SHA256SUMS"
expected="$(awk -v name="$asset" '$2 == name {print $1}' "$stage/SHA256SUMS")"
[[ "$expected" =~ ^[a-f0-9]{64}$ ]] || { echo 'Release checksum missing or ambiguous' >&2; exit 1; }
if command -v sha256sum >/dev/null; then actual="$(sha256sum "$stage/$asset" | cut -d ' ' -f1)"
else actual="$(shasum -a 256 "$stage/$asset" | cut -d ' ' -f1)"; fi
[ "$actual" = "$expected" ] || { echo 'Release checksum mismatch' >&2; exit 1; }
printf 'Tally: checksum verified. Unpacking the release...\n'
# These archives are flat and contain only the binary, documentation and installer helpers.
if tar -tzf "$stage/$asset" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then echo 'Unsafe archive paths' >&2; exit 1; fi
tar -xzf "$stage/$asset" -C "$stage"
printf 'Tally: preparing the application and databases...\n'
bash "$stage/scripts/install-runtime.sh" "$stage" "$@"
