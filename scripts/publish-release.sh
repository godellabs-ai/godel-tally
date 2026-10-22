#!/usr/bin/env bash
# Publish the GitHub release for the workspace version from a Mac. Reuses dist/v<version> only when it
# was built from HEAD with a clean tree, otherwise rebuilds all four archives. Verifies them, tags and
# pushes HEAD, uploads the archives with SHA256SUMS, then downloads and verifies the published files.
# Release notes default to the CHANGELOG.md entry; set TALLY_RELEASE_NOTES_FILE to supply your own.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
fail() { printf 'publish-release: %s\n' "$*" >&2; exit 1; }
repo="${TALLY_GITHUB_REPO:-godellabs-ai/godel-tally}"
command -v gh >/dev/null || fail 'Install the GitHub CLI, then run gh auth login'
gh auth status >/dev/null 2>&1 || fail 'Run gh auth login first'
version="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "tallyd"))')"
tag="v$version" dist="dist/v$version" head="$(git rev-parse HEAD)"
assets=(tallyd-linux-amd64.tar.gz tallyd-linux-arm64.tar.gz tallyd-darwin-amd64.tar.gz tallyd-darwin-arm64.tar.gz)

[ -z "$(git status --porcelain)" ] || fail 'Commit or stash changes first; a release must match a pushed commit'
grep -q "^## \[$version\] - " CHANGELOG.md || fail "Add a CHANGELOG.md entry for $version"
! gh release view "$tag" -R "$repo" >/dev/null 2>&1 || fail "Release $tag already exists"
git fetch --quiet origin
[ -n "$(git branch -r --contains HEAD)" ] || fail 'Push this commit to origin first'
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    [ "$(git rev-list -n 1 "$tag")" = "$head" ] || fail "Tag $tag already points to another commit"
fi
remote_tag="$(git ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}" | awk 'END {print $1}')"
[ -z "$remote_tag" ] || [ "$remote_tag" = "$head" ] || fail "Tag $tag on origin points to another commit"

if [ "$(cat "$dist/BUILD_COMMIT" 2>/dev/null || true)" = "$head" ]; then
    printf 'Reusing release archives built from %s in %s\n' "${head:0:12}" "$dist"
else
    bash scripts/build-release.sh
    [ "$(cat "$dist/BUILD_COMMIT")" = "$head" ] || fail 'The build changed tracked files; commit the generated changes and retry'
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$dist" && shasum -a 256 --check --quiet SHA256SUMS) || fail "Archives in $dist do not match SHA256SUMS"
for asset in "${assets[@]}"; do
    [ "$(grep -c "  $asset\$" "$dist/SHA256SUMS")" = 1 ] || fail "SHA256SUMS must list $asset exactly once"
    mkdir "$work/$asset" && tar -xzf "$dist/$asset" -C "$work/$asset"
    for file in install.sh uninstall.sh README.md LICENSE $(cd "$work/$asset" && ls scripts | sed 's|^|scripts/|'); do
        git show "HEAD:$file" | cmp -s - "$work/$asset/$file" || fail "$asset: $file differs from HEAD"
    done
done
case "$(uname -m)" in arm64|aarch64) host_arch=arm64 ;; *) host_arch=amd64 ;; esac
host_binary="$work/tallyd-$(uname -s | tr '[:upper:]' '[:lower:]')-$host_arch.tar.gz/tallyd"
[ "$("$host_binary" --version)" = "tallyd $version" ] || fail "The release binary does not report version $version"
"$host_binary" --check-ui >/dev/null || fail 'The release binary has no embedded UI'

if [ -n "${TALLY_RELEASE_NOTES_FILE:-}" ]; then
    cp "$TALLY_RELEASE_NOTES_FILE" "$work/notes.md"
else
    {
        awk -v heading="## [$version]" 'index($0, heading) == 1 {found = 1; next}
            found && (/^## \[/ || /^\[[0-9]/) {exit} found {print}' CHANGELOG.md
        printf '\n## Install\n\n```bash\ncurl -fsSL https://raw.githubusercontent.com/%s/%s/install.sh -o install-tally.sh\nTALLY_VERSION=%s bash install-tally.sh\n```\n' "$repo" "$tag" "$tag"
        printf '\nTo run Tally in containers instead, see the [installation guide](https://godel-labs.ai/docs/tally/installation#containers).\n'
    } > "$work/notes.md"
fi

git rev-parse -q --verify "refs/tags/$tag" >/dev/null || git tag -a "$tag" -m "Gödel Tally $version"
git push origin "refs/tags/$tag"
gh release create "$tag" -R "$repo" --verify-tag --title "Gödel Tally $version" --notes-file "$work/notes.md" \
    "${assets[@]/#/$dist/}" "$dist/SHA256SUMS"

mkdir "$work/published"
gh release download "$tag" -R "$repo" -D "$work/published"
(cd "$work/published" && shasum -a 256 --check --quiet SHA256SUMS) || fail 'Published archives do not match SHA256SUMS'
cmp -s "$work/published/SHA256SUMS" "$dist/SHA256SUMS" || fail 'Published SHA256SUMS differs from the local build'
latest="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")"
[ "${latest##*/}" = "$tag" ] || printf 'publish-release: warning: releases/latest resolves to %s, not %s\n' "${latest##*/}" "$tag" >&2
printf 'Published https://github.com/%s/releases/tag/%s\n' "$repo" "$tag"
