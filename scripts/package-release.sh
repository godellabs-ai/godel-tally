#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
case "$(uname -s)" in Darwin) host_os=darwin ;; Linux) host_os=linux ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) host_arch=amd64 ;; arm64|aarch64) host_arch=arm64 ;; *) exit 1 ;; esac
platform="${TALLY_RELEASE_PLATFORM:-$host_os-$host_arch}"
case "$platform" in linux-amd64|linux-arm64|darwin-amd64|darwin-arm64) ;; *) echo "Unsupported release platform: $platform" >&2; exit 1 ;; esac
binary="${TALLY_RELEASE_BINARY:-$root/target/release/tallyd}"
# Reject mislabeled cross-builds before writing a downloadable archive.
python3 - "$binary" "$platform" <<'PY'
from pathlib import Path
import struct
import sys
with Path(sys.argv[1]).open('rb') as binary:
    header = binary.read(20)
platform = sys.argv[2]
expected = {'linux-amd64': 62, 'linux-arm64': 183,
            'darwin-amd64': 0x01000007, 'darwin-arm64': 0x0100000c}[platform]
if platform.startswith('linux-'):
    valid = len(header) == 20 and header[:6] == b'\x7fELF\x02\x01' and struct.unpack('<H', header[18:20])[0] == expected
else:
    valid = len(header) == 20 and header[:4] == b'\xcf\xfa\xed\xfe' and struct.unpack('<I', header[4:8])[0] == expected
if not valid:
    sys.exit(f'Binary architecture does not match {platform}')
PY
if [ "$platform" = "$host_os-$host_arch" ]; then
    "$binary" --check-ui
elif [ "$platform" = darwin-amd64 ] && [ "$host_os" = darwin ] && /usr/bin/arch -x86_64 /usr/bin/true 2>/dev/null; then
    "$binary" --check-ui
else
    printf 'Cross-built %s: architecture verified; runtime smoke check requires a compatible host.\n' "$platform"
fi
output="${TALLY_RELEASE_OUTPUT_DIR:-$root/dist}"
mkdir -p "$output"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
cp "$binary" "$stage/tallyd"
cp LICENSE README.md uninstall.sh "$stage/"
mkdir "$stage/scripts"
for helper in install-runtime.sh runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do cp "scripts/$helper" "$stage/scripts/"; done
asset="tallyd-$platform.tar.gz"
# Keep macOS extended attributes/resource forks out of cross-platform archives.
COPYFILE_DISABLE=1 tar -czf "$output/$asset" -C "$stage" tallyd scripts LICENSE README.md uninstall.sh
(cd "$output"; if command -v sha256sum >/dev/null; then sha256sum "$asset"; else shasum -a 256 "$asset"; fi) > "$output/$asset.sha256"
printf 'Created %s/%s\n' "$output" "$asset"
