#!/usr/bin/env bash
# Remove Tally and its user services; retain database data unless --remove-databases is selected.
# Self-contained so it also works after a partial installation or with older release bundles.
set -euo pipefail
fail() { printf 'Tally: %s\n' "$*" >&2; exit 1; }
log() { printf 'Tally: %s\n' "$*"; }
dry_run=0; remove_databases=0
for arg in "$@"; do
    case "$arg" in
        --remove-databases) remove_databases=1 ;;
        --dry-run) dry_run=1 ;;
        --help)
            cat <<'HELP'
Uninstall Tally: bash uninstall.sh [--remove-databases] [--dry-run]
Stops and removes Tally's user services and application files. Stops database
containers owned by this installation. Retains configuration, credentials,
database data, private runtime downloads, containers, volumes, and legacy system packages.
--remove-databases also deletes Tally's private database data, owned containers
and owned volumes, downloaded private runtimes, and recorded legacy database packages.
This permanently deletes the managed Tally databases. Back up first.
Pre-existing packages, unrecorded volumes, and existing database servers are kept.
Configuration, credentials, certificates, logs and backups are retained.
New private installations never use sudo. Removing recorded legacy Linux packages may use sudo.
Use TALLY_CONFIG_DIR for a custom installation. --dry-run only shows the plan.
HELP
            exit 0 ;;
        *) fail "Unknown option: $arg" ;;
    esac
done
[ "$(id -u)" != 0 ] || fail 'Run uninstall as the user who installed Tally, without sudo.'
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) fail 'Tally supports Linux and macOS.' ;; esac
tally_home="${TALLY_HOME:-$HOME/.godel-tally}"
legacy_config="${XDG_CONFIG_HOME:-$HOME/.config}/godel-tally"
config_dir="${TALLY_CONFIG_DIR:-$tally_home/config}"
if [ -z "${TALLY_HOME:-}" ] && [ -z "${TALLY_CONFIG_DIR:-}" ] && [ ! -f "$config_dir/tally.env" ] && [ -f "$legacy_config/tally.env" ]; then config_dir="$legacy_config"; fi
config_file="$config_dir/tally.env"
saved_install_dir=
requested_install_dir="${TALLY_INSTALL_DIR:-}"
if [ -f "$config_file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        key="${line%%=*}"; value="${line#*=}"
        case "$key" in
            TALLY_INSTALL_DIR|TALLY_DATA_DIR|TALLY_RUNTIME_DIR|TALLY_POSTGRES_MODE|TALLY_CLICKHOUSE_MODE|TALLY_CONTAINER_PREFIX)
                [ "$key" != "$line" ] || fail "Invalid configuration in $config_file"
                [ "$key" != TALLY_INSTALL_DIR ] || saved_install_dir="$value"
                export "$key=$value" ;;
        esac
    done < "$config_file"
fi
install_dir="${TALLY_INSTALL_DIR:-$tally_home/app}"
data_dir="${TALLY_DATA_DIR:-$tally_home/data}"
runtime_dir="${TALLY_RUNTIME_DIR:-$tally_home/runtime}"
install_dir="${install_dir%/}"
case "$install_dir" in
    ''|/|"$HOME"|/usr|/usr/local|/usr/local/bin|/opt|/etc|/bin|/sbin|/tmp|/var|/Users|/home) fail 'Refusing an unsafe installation directory' ;;
    /*) ;;
    *) fail 'TALLY_INSTALL_DIR must be an absolute path' ;;
esac
case "$install_dir" in *$'\n'*|*$'\r'*|*/../*|*/..|*/./*|*/.) fail 'Invalid installation directory' ;; esac
[ ! -L "$install_dir" ] && [ ! -L "$install_dir/scripts" ] || fail 'Refusing a symlinked installation directory'
if [ ! -f "$config_file" ]; then
    [ ! -e "$install_dir" ] || fail "Configuration not found at $config_file; set TALLY_CONFIG_DIR to the installation's configuration directory."
    log 'No Tally installation found.'
    exit 0
fi
[ "${saved_install_dir%/}" = "$install_dir" ] || fail 'Installation directory does not match the saved configuration'
[ -z "$requested_install_dir" ] || [ "${requested_install_dir%/}" = "$install_dir" ] || fail 'TALLY_INSTALL_DIR does not match the saved configuration'

xml_escape() { local value="$1"; value="${value//&/\&amp;}"; value="${value//</\&lt;}"; value="${value//>/\&gt;}"; value="${value//\"/\&quot;}"; printf '%s' "$value"; }
service_file() {
    if [ "$os" = darwin ]; then printf '%s/Library/LaunchAgents/ai.godel.tally.%s.plist' "$HOME" "$1"
    else printf '%s/systemd/user/tally-%s.service' "${XDG_CONFIG_HOME:-$HOME/.config}" "$1"; fi
}
# Check every service before stopping anything. Never remove another installation's units.
for name in server postgres clickhouse; do
    unit="$(service_file "$name")"
    [ -e "$unit" ] || continue
    [ ! -L "$unit" ] || fail "Refusing a symlinked service file: $unit"
    if [ "$name" = server ]; then wrapper="$install_dir/tally.sh"; else wrapper="$install_dir/$name.sh"; fi
    if [ "$os" = darwin ]; then expected="<string>$(xml_escape "$wrapper")</string>"
    else
        wrapper="${wrapper//\\/\\\\}"; wrapper="${wrapper//\"/\\\"}"; wrapper="${wrapper//%/%%}"; wrapper="${wrapper//\$/\$\$}"
        expected="ExecStart=/bin/bash \"$wrapper\""
    fi
    grep -Fq -- "$expected" "$unit" || fail "Service does not belong to this installation: $unit"
done
prefix="${TALLY_CONTAINER_PREFIX:-godel-tally}"
[[ "$prefix" =~ ^[a-z0-9][a-z0-9-]*$ ]] || fail 'Invalid TALLY_CONTAINER_PREFIX'
# Validate all deletion targets and receipts before stopping services.
check_private_path() {
    local target="${1%/}" parent
    case "$target" in
        ''|/|"$HOME"|/usr|/usr/local|/usr/local/bin|/opt|/etc|/bin|/sbin|/tmp|/var|/Users|/home|/var/lib|/usr/local/var|/opt/homebrew/var) fail "Unsafe database cleanup path: $target" ;;
        /*) ;; *) fail 'Database cleanup paths must be absolute' ;;
    esac
    case "$target" in *$'\n'*|*$'\r'*|*/../*|*/..|*/./*|*/.|*//*) fail "Invalid database cleanup path: $target" ;; esac
    case "$HOME/" in "$target/"*) fail 'Database cleanup path contains the home directory' ;; esac
    parent="$target"
    while [ "$parent" != / ]; do
        # macOS ships these three system aliases; user-controlled symlinks are refused.
        case "$parent" in /tmp|/var|/etc) ;; *) [ ! -L "$parent" ] || fail "Refusing symlinked cleanup path: $parent" ;; esac
        parent="$(dirname "$parent")"
    done
}
package_receipt="$config_dir/installed-packages"
if [ "$remove_databases" = 1 ]; then
    check_private_path "$data_dir"
    check_private_path "$config_dir"
    check_private_path "$install_dir"
    check_private_path "$runtime_dir"
    for protected in "$data_dir" "$config_dir" "$install_dir"; do
        case "$protected/" in "$runtime_dir/"*) fail 'Runtime cleanup directory contains settings, data, or application files' ;; esac
    done
    if [ -e "$runtime_dir" ]; then
        [ -f "$runtime_dir/.tally-runtime" ] && [ ! -L "$runtime_dir/.tally-runtime" ] && [ "$(cat "$runtime_dir/.tally-runtime")" = "$config_dir" ] || fail 'Private runtime ownership marker is missing or belongs to another installation; refusing runtime cleanup'
    fi
    [ ! -L "$package_receipt" ] || fail 'Refusing a symlinked package receipt'
    for db in postgres clickhouse; do
        check_private_path "$data_dir/$db"
        check_private_path "$data_dir/containers"
        case "$config_dir/" in "$data_dir/$db/"*) fail 'Database directory contains configuration' ;; esac
        case "$install_dir/" in "$data_dir/$db/"*) fail 'Database directory contains application files' ;; esac
        if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-existing}"; else mode="${TALLY_CLICKHOUSE_MODE:-existing}"; fi
        case "$mode" in
            docker) engine=docker ;;
            apple) engine=container ;;
            native|existing) continue ;;
            *) fail 'Invalid saved database mode' ;;
        esac
        volume_receipt="$data_dir/containers/$engine-$prefix-$db.volume"
        [ ! -L "$volume_receipt" ] || fail 'Refusing a symlinked volume receipt'
        if [ -f "$volume_receipt" ]; then
            volume="$(cat "$volume_receipt")"
            [[ "$volume" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]] || fail 'Invalid volume ownership receipt'
        fi
    done
    if [ -f "$package_receipt" ]; then
        while IFS= read -r receipt || [ -n "$receipt" ]; do
            case "$receipt" in
                'brew-formula|postgres|postgresql@18'|'brew-cask|clickhouse|clickhouse'|\
                'apt|postgres|postgresql-18'|'apt|postgres|postgresql-client-18'|\
                'dnf|postgres|postgresql18-server'|'dnf|postgres|postgresql18'|'dnf|postgres|postgresql-server'|'dnf|postgres|postgresql'|\
                'yum|postgres|postgresql18-server'|'yum|postgres|postgresql18'|'yum|postgres|postgresql-server'|'yum|postgres|postgresql'|\
                'apt|clickhouse|clickhouse-server'|'apt|clickhouse|clickhouse-client'|'apt|clickhouse|clickhouse-common-static'|\
                'dnf|clickhouse|clickhouse-server'|'dnf|clickhouse|clickhouse-client'|'dnf|clickhouse|clickhouse-common-static'|\
                'yum|clickhouse|clickhouse-server'|'yum|clickhouse|clickhouse-client'|'yum|clickhouse|clickhouse-common-static') ;;
                *) fail "Invalid package ownership receipt: $receipt" ;;
            esac
            case "$os:$receipt" in darwin:brew-*|linux:apt\|*|linux:dnf\|*|linux:yum\|*) ;; *) fail 'Package receipt does not match this operating system' ;; esac
        done < "$package_receipt"
    fi
fi
log "Remove application files from $install_dir"
log "Keep configuration and credentials in $config_dir"
if [ "$remove_databases" = 1 ]; then
    log 'Permanently remove managed database data and recorded database packages/volumes.'
    log "Keep certificates, logs and backups in $data_dir"
else
    log "Keep database data and certificates in $data_dir"
    log 'Database packages and container volumes will be kept.'
fi
units_removed=0; server_booted_out=0
for name in server postgres clickhouse; do
    unit="$(service_file "$name")"
    [ -e "$unit" ] || continue
    log "Stop and remove the Tally $name user service"
    [ "$dry_run" = 0 ] || continue
    if [ "$os" = darwin ]; then
        label="gui/$(id -u)/ai.godel.tally.$name"
        if launchctl print "$label" >/dev/null 2>&1; then
            launchctl bootout "$label"
            [ "$name" != server ] || server_booted_out=1
        fi
    else
        systemctl --user disable --now "tally-$name.service"
    fi
    rm -f "$unit"
    units_removed=1
done
for db in postgres clickhouse; do
    if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-existing}"; else mode="${TALLY_CLICKHOUSE_MODE:-existing}"; fi
    case "$mode" in docker) engine=docker ;; apple) engine=container ;; *) continue ;; esac
    name="$prefix-$db"
    marker="$data_dir/containers/$engine-$name"
    [ -f "$marker" ] || { [ "$remove_databases" = 1 ] && [ -f "$marker.volume" ]; } || continue
    log "Stop the owned database container $name"
    if [ "$remove_databases" = 1 ]; then
        log "Remove owned container $name"
        if [ -f "$marker.volume" ]; then log "Remove owned volume $(cat "$marker.volume")"
        else log "Keep volumes for $name: no volume ownership receipt exists"; fi
    fi
    [ "$dry_run" = 0 ] || continue
    command -v "$engine" >/dev/null || fail "Start $engine and rerun uninstall to stop the owned database containers"
    if [ "$engine" = docker ]; then
        docker info >/dev/null || fail 'Start Docker and rerun uninstall'
        if [ -f "$marker" ] && docker inspect "$name" >/dev/null 2>&1 && [ "$(docker inspect --format '{{.State.Running}}' "$name")" = true ]; then docker stop "$name"; fi
    else
        running="$(container ls --quiet)" || fail 'Start Apple container and rerun uninstall'
        if [ -f "$marker" ] && printf '%s\n' "$running" | grep -Fxq "$name"; then container stop "$name"; fi
    fi
    if [ "$remove_databases" = 1 ]; then
        if [ -f "$marker" ] && "$engine" inspect "$name" >/dev/null 2>&1; then
            if [ "$engine" = docker ]; then "$engine" rm "$name"; else "$engine" delete "$name"; fi
        fi
        if [ -f "$marker.volume" ]; then
            volume="$(cat "$marker.volume")"
            if "$engine" volume inspect "$volume" >/dev/null 2>&1; then "$engine" volume rm "$volume"; fi
            rm -f "$marker.volume"
        fi
        rm -f "$marker"
    fi
done
# A manually started supervisor must be stopped before removing its files or data.
verified_stopped=0
if [ "$dry_run" = 0 ] && [ -f "$data_dir/supervisor.lock" ]; then
    [ -x "$install_dir/tallyd" ] || fail 'Cannot verify whether Tally is stopped. Reinstall its application binary before database cleanup.'
    stop_hint='Stop its manual session with Ctrl+C'
    if [ "$server_booted_out" = 1 ]; then
        # launchctl bootout returns while the supervisor is still stopping its databases and
        # holding its lock. Allow launchd's 90-second ExitTimeOut before reporting it as running.
        for attempt in $(seq 1 95); do
            if "$install_dir/tallyd" check-stopped "$data_dir" >/dev/null 2>&1; then break; fi
            [ "$attempt" != 1 ] || log 'Waiting for the Tally service to finish stopping...'
            sleep 1
        done
        stop_hint="The service did not stop; check $data_dir/server.log"
    fi
    "$install_dir/tallyd" check-stopped "$data_dir" || fail "Tally is still running. $stop_hint, then retry uninstall."
    verified_stopped=1
fi
if [ "$remove_databases" = 1 ]; then
    if [ -f "$runtime_dir/.tally-runtime" ]; then
        log "Remove downloaded private database runtimes: $runtime_dir"
        [ "$dry_run" = 1 ] || rm -rf -- "$runtime_dir"
    fi
    deb_packages=(); rpm_packages=()
    if [ -f "$package_receipt" ]; then
        while IFS='|' read -r manager db package; do
            if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-existing}"; else mode="${TALLY_CLICKHOUSE_MODE:-existing}"; fi
            [ "$mode" = native ] || continue
            log "Remove installer-owned package $package ($manager)"
            [ "$dry_run" = 0 ] || continue
            case "$manager" in
                brew-formula) if brew list --formula "$package" >/dev/null 2>&1; then HOMEBREW_NO_AUTOREMOVE=1 brew uninstall --formula "$package"; fi ;;
                brew-cask) if brew list --cask "$package" >/dev/null 2>&1; then HOMEBREW_NO_AUTOREMOVE=1 brew uninstall --cask "$package"; fi ;;
                apt) if [ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null)" = 'install ok installed' ]; then deb_packages+=("$package"); fi ;;
                dnf|yum) if rpm -q "$package" >/dev/null 2>&1; then rpm_packages+=("$package"); fi ;;
            esac
        done < "$package_receipt"
        # Low-level removal refuses external dependents instead of cascading into unowned packages.
        if [ "${#deb_packages[@]}" -gt 0 ]; then sudo dpkg --remove "${deb_packages[@]}"; fi
        if [ "${#rpm_packages[@]}" -gt 0 ]; then sudo rpm -e "${rpm_packages[@]}"; fi
    else
        log 'Keep database packages: this installation has no package ownership receipt.'
    fi
    for db in postgres clickhouse; do
        if [ "$db" = postgres ]; then mode="${TALLY_POSTGRES_MODE:-existing}"; else mode="${TALLY_CLICKHOUSE_MODE:-existing}"; fi
        [ "$mode" = native ] || continue
        log "Delete private database data: $data_dir/$db"
        [ "$dry_run" = 0 ] || continue
        rm -rf -- "$data_dir/$db"
        if [ "$db" = clickhouse ]; then rm -f "$config_dir/clickhouse.xml"; fi
    done
    [ "$dry_run" = 1 ] || rm -f "$package_receipt"
fi
if [ "$dry_run" = 1 ]; then log 'Dry run complete; no changes made.'; exit 0; fi
if [ "$os" = linux ] && [ "$units_removed" = 1 ]; then systemctl --user daemon-reload; fi
# Remove only known application files, preserving anything an operator added.
for helper in runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh download-databases.sh database-assets.tsv upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do
    rm -f "$install_dir/scripts/$helper"
done
rm -f "$install_dir/tallyd" "$install_dir/tallyd.new" "$install_dir/tally.sh" "$install_dir/postgres.sh" "$install_dir/clickhouse.sh" "$install_dir/uninstall.sh"
rmdir "$install_dir/scripts" "$install_dir" 2>/dev/null || true
# A clean uninstall has removed the launcher and verified that no children remain.
# Retaining this empty lock would require a now-removed binary on a later cleanup.
[ "$verified_stopped" = 0 ] || rm -f "$data_dir/supervisor.lock"
if [ "$remove_databases" = 1 ]; then log 'Tally uninstalled and managed database cleanup completed. Configuration and certificates were retained.'
else log 'Tally uninstalled. Rerun the installer to reuse the retained configuration and databases.'; fi
