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
file_size() { if [ -f "$1" ]; then wc -c < "$1" | tr -d ' '; else printf '0\n'; fi; }
megabytes() { awk -v bytes="$1" 'BEGIN { printf "%.1f", bytes / 1048576 }'; }
# Every listed source serves the same pinned bytes, so one partial file resumes from any of them.
load_asset() {
    local row url
    row="$(awk -F '|' -v db="$1" -v platform="$platform" '$1==db && $2==platform {print}' "$script_dir/database-assets.tsv")"
    [ "$(printf '%s\n' "$row" | wc -l | tr -d ' ')" = 1 ] && [ -n "$row" ] || fail "No unique pinned $1 download for $platform"
    IFS='|' read -r component target version format archive_root digest size urls <<< "$row"
    [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+([.][0-9]+)?$ && "$digest" =~ ^[a-f0-9]{64}$ && "$size" =~ ^[1-9][0-9]*$ ]] || fail 'Invalid database manifest'
    read -r -a sources <<< "$urls"
    [ "${#sources[@]}" -gt 0 ] || fail 'Invalid database manifest'
    for url in "${sources[@]}"; do
        case "$url" in https://packages.clickhouse.com/tgz/stable/*|https://github.com/theseus-rs/postgresql-binaries/releases/download/*|https://github.com/ClickHouse/ClickHouse/releases/download/*) ;; *) fail 'Unexpected database download host' ;; esac
    done
    partial="$TALLY_RUNTIME_DIR/.partial-$1-$digest"
}
# Each attempt continues the partial file, so a dropped connection keeps what already arrived.
download_archive() {
    local attempt=1 i status
    while :; do
        for i in "${!sources[@]}"; do
            status=0
            curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS -C - --connect-timeout 30 \
                --speed-limit 10240 --speed-time 60 "${sources[$i]}" -o "$partial" &
            transfer=$!
            wait "$transfer" || status=$?
            [ "$status" != 0 ] || return 0
            # The server ignored the byte range, so appending would corrupt the archive.
            [ "$status" != 33 ] || : > "$partial"
            [ "$((i + 1))" = "${#sources[@]}" ] || printf '  > Trying the next official %s download source...\n' "$db"
        done
        [ "$attempt" -lt 5 ] || return 1
        printf '  > The %s download was interrupted. Resuming in %ss (attempt %s of 5)...\n' "$db" "$((attempt * 5))" "$((attempt + 1))"
        sleep "$((attempt * 5))"
        attempt=$((attempt + 1))
    done
}
# Always started with &. Braces keep $! on this process: a ( ) body forks again and the kill misses it.
# It ends with an explicit exit because bash 3.2 skips the EXIT trap when a background job just finishes.
fetch_database() {
    db="$1"
    # Background jobs ignore Ctrl+C, so stop the transfer before a rerun can append to the same partial file.
    transfer=
    trap '[ -z "$transfer" ] || { kill "$transfer" 2>/dev/null; wait "$transfer" 2>/dev/null; }; exit 143' TERM
    load_asset "$db"
    destination="$TALLY_RUNTIME_DIR/$db-$version-$platform"
    if [ "$db" = postgres ]; then executable=bin/postgres; else executable=bin/clickhouse; fi
    if [ -f "$destination/.archive-sha256" ] && [ "$(cat "$destination/.archive-sha256")" = "$digest" ] && [ -x "$destination/$executable" ]; then
        printf '  OK Reusing private %s %s.\n' "$db" "$version"
        printf '%s\n' "$destination" > "$TALLY_RUNTIME_DIR/$db.path"
        exit 0
    fi
    [ ! -e "$destination" ] || fail "Incomplete runtime at $destination. Move that directory aside and retry; keep your database data."
    for stale in "$TALLY_RUNTIME_DIR/.partial-$db-"*; do [ "$stale" = "$partial" ] || rm -f "$stale"; done
    # Resuming cannot repair a partial file that is already longer than the pinned archive.
    [ "$(file_size "$partial")" -le "$size" ] || : > "$partial"
    received="$(file_size "$partial")"
    if [ "$received" = 0 ]; then printf '  > Downloading private %s %s (%s MB)...\n' "$db" "$version" "$(megabytes "$size")"
    else printf '  > Resuming private %s %s (%s of %s MB already downloaded)...\n' "$db" "$version" "$(megabytes "$received")" "$(megabytes "$size")"; fi
    : >> "$partial"
    if [ "$received" -lt "$size" ]; then
        download_archive || fail "$db could not be downloaded. Check your internet connection, then rerun the installer; it resumes where this download stopped."
    fi
    if [ "$(sha256_file "$partial")" != "$digest" ]; then rm -f "$partial"; fail "$db download checksum mismatch; rerun the installer"; fi
    stage="$(mktemp -d "$TALLY_RUNTIME_DIR/.download-$db.XXXXXX")"
    trap 'rm -rf "$stage"' EXIT
    mv "$partial" "$stage/archive"
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
    exit 0
}
# Received bytes and throughput tell a slow connection apart from a stalled one.
report_progress() {
    local interval="$1" i received delta=0 downloading=0 details=
    for i in "${!pids[@]}"; do
        kill -0 "${pids[$i]}" 2>/dev/null || continue
        if [ ! -f "${partials[$i]}" ]; then details="$details, ${dbs[$i]} unpacking"; continue; fi
        received="$(file_size "${partials[$i]}")"
        if [ "$received" -ge "${sizes[$i]}" ]; then details="$details, ${dbs[$i]} verifying"
        else details="$details, ${dbs[$i]} $(megabytes "$received") of $(megabytes "${sizes[$i]}") MB"; downloading=1; fi
        [ "$received" -lt "${seen[$i]}" ] || delta=$((delta + received - ${seen[$i]}))
        seen[$i]="$received"
    done
    [ -n "$details" ] || return 0
    if [ "$downloading" = 1 ]; then details="$details, $(megabytes "$((delta / interval))") MB/s"; fi
    printf '  > Still preparing private databases (%ss elapsed): %s.\n' "$((SECONDS - began))" "${details#, }"
}
pids=(); dbs=(); partials=(); sizes=(); seen=()
# Wait for every transfer to stop before the lock is released.
cleanup_downloads() { local pid; for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2>/dev/null || true; done; wait; }
trap 'cleanup_downloads; exit 130' INT
trap 'cleanup_downloads; exit 143' TERM
# Validate every manifest row before any download starts.
for db in postgres clickhouse; do
    if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-native}"; else mode="${TALLY_CLICKHOUSE_MODE:-native}"; fi
    [ "$mode" = native ] || continue
    load_asset "$db"
    dbs+=("$db"); partials+=("$partial"); sizes+=("$size"); seen+=("$(file_size "$partial")")
done
status=0
if [ "${#dbs[@]}" -gt 0 ]; then
    for db in "${dbs[@]}"; do fetch_database "$db" & pids+=("$!"); done
    began=$SECONDS; reported=$SECONDS
    while :; do
        active=0
        for pid in "${pids[@]}"; do if kill -0 "$pid" 2>/dev/null; then active=1; fi; done
        [ "$active" = 1 ] || break
        sleep 1
        if [ "$((SECONDS - reported))" -ge 10 ]; then
            report_progress "$((SECONDS - reported))"
            reported=$SECONDS
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || status=1; done
fi
exit "$status"
