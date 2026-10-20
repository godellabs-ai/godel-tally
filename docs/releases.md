# Build and publish a release locally

Tally does not use GitHub Actions. Build the four release archives on a Mac with the repository's
Rust toolchain, Node.js, Python 3, CMake, and Xcode command-line tools. The web console is compiled
into each binary. GitHub is used to host source code and release downloads.

Install the cross-compilation tools in an isolated environment:

```bash
python3 -m venv .local/release-tools
.local/release-tools/bin/pip install cargo-zigbuild
export PATH="$PWD/.local/release-tools/bin:$PATH"
export CARGO_ZIGBUILD_PYTHON_PATH="$PWD/.local/release-tools/bin/python"
make release-local
```

`cargo-zigbuild` installs Zig as a dependency and cross-compiles the static Linux binaries.
macOS builds use Apple's compiler and SDK. `CARGO_BUILD_JOBS` defaults to 2; lower it if memory
is limited. Artifacts are written to `dist/v<workspace-version>/`, with a combined `SHA256SUMS`.
The script builds and packages only; it does not start services or publish.

## Validate

Run `make web-install`, `make check`, and `bash scripts/test-deployment.sh`. Packaging verifies
each executable's architecture and checks the embedded UI when the host can execute it.
Cross-compilation alone does not establish that a binary runs on its target.

On a compatible Mac, run each macOS executable with `--version`, `--check-ui`, and `collector check`.
An Apple Silicon Mac needs Rosetta to execute the Intel binary.

Linux binaries can be checked on Linux hosts or in disposable Docker containers. For example,
after extracting an archive into an absolute directory:

```bash
docker run --rm --platform linux/arm64 --network none --read-only \
  --cap-drop ALL -v "/absolute/extracted/tallyd:/tallyd:ro" \
  debian:trixie-slim /tallyd --check-ui
```

Use `linux/amd64` for the other Linux archive, and also run `--version` and `collector check`.
This checks the binary without starting databases or Tally services. Test native database
provisioning on a disposable machine; never run the installer against a developer's existing
services just to validate a release.

## Publish

Update version metadata and the changelog, regenerate registry/schema artifacts, and commit and
push all changes before tagging. Upload only the four validated archives and their checksum file:

```bash
version=v0.1.1
git tag -a "$version" -m "Gödel Tally $version"
git push origin "$version"
gh release create "$version" --verify-tag --draft \
  --title "Gödel Tally $version" --notes-file /absolute/release-notes.md \
  "dist/$version/"*.tar.gz "dist/$version/SHA256SUMS"
gh release edit "$version" --draft=false --latest
```

After publication, verify anonymous downloads, checksums, and the public `install.sh` command.
