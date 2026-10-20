#!/usr/bin/env bash
# Exercise real Homebrew provisioning and LaunchAgents only on a disposable GitHub runner.
set -euo pipefail
[ "${GITHUB_ACTIONS:-}" = true ] && [ "$(uname -s)" = Darwin ] || {
    echo 'This test runs only on disposable macOS GitHub Actions runners.' >&2; exit 1;
}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
test_root="$(mktemp -d "$RUNNER_TEMP/tally-native-install.XXXXXX")"
export TALLY_INSTALL_DIR="$test_root/install" TALLY_CONFIG_DIR="$test_root/config" TALLY_DATA_DIR="$test_root/data"
export HOMEBREW_NO_AUTO_UPDATE=1
cleanup() {
    result=$?
    if [ "$result" != 0 ]; then
        for name in server postgres clickhouse; do
            [ ! -f "$TALLY_DATA_DIR/$name.log" ] || tail -n 60 "$TALLY_DATA_DIR/$name.log"
        done
    fi
    if [ -f "$TALLY_CONFIG_DIR/tally.env" ]; then
        bash "$root/uninstall.sh" || result=1
    fi
    exit "$result"
}
trap cleanup EXIT
mkdir "$test_root/bundle"
tar -xzf "$root/dist/tallyd-darwin-arm64.tar.gz" -C "$test_root/bundle"
bash "$test_root/bundle/scripts/install-runtime.sh" "$test_root/bundle"
curl --fail --silent --show-error --cacert "$TALLY_DATA_DIR/tls/tally.crt" https://localhost:8443/ -o "$test_root/index.html"
grep -qi '<!doctype html' "$test_root/index.html"
"$TALLY_INSTALL_DIR/tallyd" --version
echo 'Native Homebrew installation, database migrations, HTTPS UI, and LaunchAgent startup passed.'
