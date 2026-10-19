#!/usr/bin/env bash
# Source from dev-run.sh with REPO_DIR set. Watch build inputs explicitly:
# macOS can report the repository root after a stopped watcher resumes, even
# when only ignored .local files changed. Watching that root defeats ignores.
TALLY_RUST_WATCH_ARGS=(
    --why
    --watch Cargo.toml
    --watch Cargo.lock
    --watch rust-toolchain.toml
    --watch crates
    --watch apps/tallyd
    --watch apps/tally-collector
    --watch apps/tally-upgrade
    --watch apps/tally-registry
    --watch registry-data
    --watch testdata
    --ignore '.local/**'
    --ignore 'apps/web/**'
    --ignore '**/__pycache__/**'
    --ignore '**/*.pyc'
)
if [ -d "${REPO_DIR:?REPO_DIR must be set}/.cargo" ]; then
    TALLY_RUST_WATCH_ARGS+=(--watch .cargo)
fi
