#!/usr/bin/env bash
# Build all four release archives locally on macOS. Does not publish or start services.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
[ "$(uname -s)" = Darwin ] || { echo 'The four-platform build requires a Mac with Xcode command-line tools.' >&2; exit 1; }
if ! command -v cargo-zigbuild >/dev/null; then
    command -v uv >/dev/null || { echo 'Install cargo-zigbuild and Zig; see https://godel-labs.ai/docs/tally/development#release-builds.' >&2; exit 1; }
    exec uv run --no-project --with cargo-zigbuild -- bash "$0" "$@"
fi
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "tallyd"))')"
export TALLY_RELEASE_OUTPUT_DIR="${TALLY_RELEASE_OUTPUT_DIR:-$root/dist/v$version}"
# Record the source only for a clean tree; publish-release.sh reuses archives built from HEAD.
build_commit=uncommitted-changes
[ -n "$(git status --porcelain)" ] || build_commit="$(git rev-parse HEAD)"
rm -f "$TALLY_RELEASE_OUTPUT_DIR/BUILD_COMMIT"
rustup target add aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl
make web-install web-build registry-build
for platform in linux-arm64 linux-amd64 darwin-arm64 darwin-amd64; do
    case "$platform" in
        linux-arm64) target=aarch64-unknown-linux-musl ;;
        linux-amd64) target=x86_64-unknown-linux-musl ;;
        darwin-arm64) target=aarch64-apple-darwin ;;
        darwin-amd64) target=x86_64-apple-darwin ;;
    esac
    printf '\nBuilding Tally %s for %s...\n' "$version" "$platform"
    case "$platform" in linux-*) cargo_command=zigbuild ;; *) cargo_command=build ;; esac
    cargo "$cargo_command" --locked --profile container -p tallyd --features embedded-ui --target "$target"
    TALLY_RELEASE_PLATFORM="$platform" TALLY_RELEASE_BINARY="$root/target/$target/container/tallyd" bash scripts/package-release.sh
done
# Generated inputs that changed during the build also mean the archives do not match HEAD.
[ -z "$(git status --porcelain)" ] || build_commit=uncommitted-changes
(
    cd "$TALLY_RELEASE_OUTPUT_DIR"
    cat tallyd-{linux,darwin}-{amd64,arm64}.tar.gz.sha256 > SHA256SUMS
    shasum -a 256 --check SHA256SUMS
    printf '%s\n' "$build_commit" > BUILD_COMMIT
)
printf '\nRelease archives: %s\nSee https://godel-labs.ai/docs/tally/development#release-builds for runtime checks and manual publication.\n' "$TALLY_RELEASE_OUTPUT_DIR"
