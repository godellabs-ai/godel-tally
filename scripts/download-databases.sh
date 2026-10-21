#!/usr/bin/env bash
# Private, versioned database runtimes. Never installs system packages or starts servers.
set -euo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$script_dir/runtime-common.sh"
: "${TALLY_RUNTIME_DIR:?private runtime directory required}"
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) fail 'Unsupported database platform' ;; esac
case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=amd64 ;; *) fail 'Unsupported database architecture' ;; esac
platform="$os-$arch"
# These are the documented ABI requirements of the pinned PostgreSQL distribution.
if [ "${TALLY_POSTGRES_MODE:-native}" = native ]; then
    if [ "$os" = darwin ]; then
        [ "$(sw_vers -productVersion | cut -d. -f1)" -ge 15 ] || fail 'Private PostgreSQL requires macOS 15+. Use Docker or existing databases on older systems.'
    else
        libc="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
        version="${libc#glibc }"; major="${version%%.*}"; minor="${version#*.}"
        [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] && { [ "$major" -gt 2 ] || { [ "$major" = 2 ] && [ "$minor" -ge 36 ]; }; } || fail 'Private PostgreSQL requires Linux with glibc 2.36+ (such as Debian 12 or Ubuntu 24.04). Use Docker or existing databases elsewhere.'
    fi
fi
umask 077
mkdir -p "$TALLY_RUNTIME_DIR"
[ ! -L "$TALLY_RUNTIME_DIR" ] || fail 'The private runtime directory must not be a symlink'
lock="$TALLY_RUNTIME_DIR/.download-lock"
mkdir "$lock" 2>/dev/null || fail "Another download may be running. Wait for it to finish; after an interrupted installation, remove $lock and retry."
trap 'rmdir "$lock"' EXIT
owner="${TALLY_CONFIG_DIR:?configuration directory required}"
if [ -e "$TALLY_RUNTIME_DIR/.tally-runtime" ]; then
    [ ! -L "$TALLY_RUNTIME_DIR/.tally-runtime" ] && [ "$(cat "$TALLY_RUNTIME_DIR/.tally-runtime")" = "$owner" ] || fail 'This runtime directory belongs to another installation. Choose a separate TALLY_RUNTIME_DIR.'
else printf '%s\n' "$owner" > "$TALLY_RUNTIME_DIR/.tally-runtime"; fi
sha256_file() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f1
    else shasum -a 256 "$1" | cut -d ' ' -f1; fi
}
fetch_database() (
    db="$1"
    row="$(awk -F '|' -v db="$db" -v platform="$platform" '$1==db && $2==platform {print}' "$script_dir/database-assets.tsv")"
    [ "$(printf '%s\n' "$row" | wc -l | tr -d ' ')" = 1 ] && [ -n "$row" ] || fail "No unique pinned $db download for $platform"
    IFS='|' read -r component target version format archive_root digest url <<< "$row"
    [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?$ && "$digest" =~ ^[a-f0-9]{64}$ ]] || fail 'Invalid database manifest'
    case "$url" in https://github.com/theseus-rs/postgresql-binaries/releases/download/*|https://github.com/ClickHouse/ClickHouse/releases/download/*) ;; *) fail 'Unexpected database download host' ;; esac
    destination="$TALLY_RUNTIME_DIR/$db-$version-$platform"
    if [ "$db" = postgres ]; then executable=bin/postgres; else executable=bin/clickhouse; fi
    if [ -f "$destination/.archive-sha256" ] && [ "$(cat "$destination/.archive-sha256")" = "$digest" ] && [ -x "$destination/$executable" ]; then
        printf '  OK Reusing private %s %s.\n' "$db" "$version"
        printf '%s\n' "$destination" > "$TALLY_RUNTIME_DIR/$db.path"
        exit 0
    fi
    [ ! -e "$destination" ] || fail "Incomplete runtime at $destination. Move that directory aside and retry; keep your database data."
    stage="$(mktemp -d "$TALLY_RUNTIME_DIR/.download-$db.XXXXXX")"
    trap 'rm -rf "$stage"' EXIT
    printf '  > Downloading private %s %s...\n' "$db" "$version"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --retry 3 "$url" -o "$stage/archive"
    [ "$(sha256_file "$stage/archive")" = "$digest" ] || fail "$db download checksum mismatch; rerun the installer"
    mkdir "$stage/runtime"
    if [ "$format" = tar ]; then
        tar -tzf "$stage/archive" > "$stage/entries"
        if grep -Eq '(^/|(^|/)\.\.(/|$))' "$stage/entries"; then fail 'Unsafe database archive path'; fi
        tar -xzf "$stage/archive" -C "$stage/runtime"
        if [ "$db" = postgres ]; then mv "$stage/runtime/$archive_root" "$stage/ready"
        else
            mkdir -p "$stage/ready/bin"
            mv "$stage/runtime/$archive_root/clickhouse" "$stage/ready/bin/clickhouse"
            # Keep upstream notices accompanying the official distribution.
            if [ -d "$stage/runtime/clickhouse-common-static-$version/usr/share" ]; then
                mv "$stage/runtime/clickhouse-common-static-$version/usr/share" "$stage/ready/share"
            fi
        fi
    elif [ "$format" = binary ] && [ "$db" = clickhouse ]; then
        mkdir -p "$stage/ready/bin"
        mv "$stage/archive" "$stage/ready/bin/clickhouse"
    else fail 'Unsupported database archive format'; fi
    chmod 755 "$stage/ready/$executable"
    "$stage/ready/$executable" --version >/dev/null
    printf '%s\n' "$digest" > "$stage/ready/.archive-sha256"
    mv "$stage/ready" "$destination"
    printf '%s\n' "$destination" > "$TALLY_RUNTIME_DIR/$db.path"
    printf '  OK Private %s %s downloaded and verified.\n' "$db" "$version"
)
pids=()
cleanup_downloads() { local pid; for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap 'cleanup_downloads; exit 130' INT
trap 'cleanup_downloads; exit 143' TERM
for db in postgres clickhouse; do
    if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-native}"; else mode="${TALLY_CLICKHOUSE_MODE:-native}"; fi
    [ "$mode" = native ] || continue
    fetch_database "$db" & pids+=("$!")
done
status=0
if [ "${#pids[@]}" -gt 0 ]; then
    started=$SECONDS
    while :; do
        active=0
        for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then active=1; fi; done
        [ "$active" = 1 ] || break
        sleep 1
        elapsed=$((SECONDS - started))
        if [ "$elapsed" -ge 10 ]; then
            printf '  > Still downloading or verifying private databases (%ss elapsed). Large files can take a few minutes.\n' "$SECONDS"
            started=$SECONDS
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || status=1; done
fi
exit "$status"
