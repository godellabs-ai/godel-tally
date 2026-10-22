#!/usr/bin/env bash
# Publish the Tally container image for linux/amd64 and linux/arm64. Requires `docker login quay.io`.
# tallyd is cross-compiled on the host, as for release archives, so the AMD64 image does not compile
# Rust under emulation. Architecture tags are pushed first; the version tag is updated only after both.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
fail() { printf 'push-image: %s\n' "$*" >&2; exit 1; }
if ! command -v cargo-zigbuild >/dev/null; then
    command -v uv >/dev/null || fail 'Install cargo-zigbuild and Zig, for example: uv tool install cargo-zigbuild'
    exec uv run --no-project --with cargo-zigbuild -- bash "$0" "$@"
fi
docker buildx version >/dev/null || fail 'Docker Buildx is required'
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "tallyd"))')"
image="${TALLY_IMAGE_PREFIX:-quay.io/godellabs-ai}/godel-tally"
# The downloadable Compose file pins this tag; publishing another version would leave it unpullable.
grep -Fq "godel-tally:\${TALLY_IMAGE_TAG:-$version}" docker-compose.yml || fail "docker-compose.yml must default to image tag $version"
[ -z "$(git status --porcelain)" ] || printf 'push-image: warning: publishing from a working tree with uncommitted changes\n' >&2
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl
make web-install web-build registry-build
binaries="$(mktemp -d)"
trap 'rm -rf "$binaries"' EXIT
for arch in amd64 arm64; do
    case "$arch" in
        amd64) target=x86_64-unknown-linux-musl; machine=x86-64 ;;
        arm64) target=aarch64-unknown-linux-musl; machine=aarch64 ;;
    esac
    printf '\nBuilding tallyd %s for linux/%s...\n' "$version" "$arch"
    cargo zigbuild --locked --profile container -p tallyd --features embedded-ui --target "$target"
    mkdir "$binaries/linux-$arch"
    cp "target/$target/container/tallyd" "$binaries/linux-$arch/tallyd"
    file -b "$binaries/linux-$arch/tallyd" | grep -q "ELF 64-bit.*$machine" || fail "tallyd for linux/$arch has the wrong architecture"
done
for arch in amd64 arm64; do
    printf '\nPublishing %s:%s-%s...\n' "$image" "$version" "$arch"
    docker buildx build --platform "linux/$arch" --file deploy/compose/Dockerfile.tallyd \
        --build-arg TALLYD_BINARY_STAGE=prebuilt --build-context "tallyd-binaries=$binaries" \
        --tag "$image:$version-$arch" --push .
done
printf '\nPublishing the amd64 + arm64 manifest for %s:%s...\n' "$image" "$version"
docker buildx imagetools create --tag "$image:$version" "$image:$version-amd64" "$image:$version-arm64"
platforms="$(docker buildx imagetools inspect "$image:$version" --format \
    '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}}{{"\n"}}{{end}}')"
for arch in amd64 arm64; do
    grep -qx "linux/$arch" <<< "$platforms" || fail "$image:$version is missing linux/$arch"
done
printf '\nPublished %s:%s for linux/amd64 and linux/arm64.\n' "$image" "$version"
printf 'A new Quay repository is private by default; make it public so deployments can pull anonymously.\n'
