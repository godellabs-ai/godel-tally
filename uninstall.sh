#!/usr/bin/env bash
# Remove Tally's application and user services, retaining configuration and all database data.
# Self-contained so it also works after a partial installation or with older release bundles.
set -euo pipefail
fail() { printf 'Tally: %s\n' "$*" >&2; exit 1; }
log() { printf 'Tally: %s\n' "$*"; }
dry_run=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) dry_run=1 ;;
        --help)
            cat <<'HELP'
Uninstall Tally: bash uninstall.sh [--dry-run]
Stops and removes Tally's user services and application files. Stops database
containers owned by this installation. Retains configuration, credentials,
database data, containers, volumes, and installed PostgreSQL/ClickHouse packages.
Existing/shared database servers are never changed. No sudo is required.
Use TALLY_CONFIG_DIR for a custom installation. --dry-run only shows the plan.
HELP
            exit 0 ;;
        *) fail "Unknown option: $arg" ;;
    esac
done
[ "$(id -u)" != 0 ] || fail 'Run uninstall as the user who installed Tally, without sudo.'
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) fail 'Tally supports Linux and macOS.' ;; esac
config_dir="${TALLY_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/godel-tally}"
config_file="$config_dir/tally.env"
saved_install_dir=
requested_install_dir="${TALLY_INSTALL_DIR:-}"
if [ -f "$config_file" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        key="${line%%=*}"; value="${line#*=}"
        case "$key" in
            TALLY_INSTALL_DIR|TALLY_DATA_DIR|TALLY_POSTGRES_MODE|TALLY_CLICKHOUSE_MODE|TALLY_CONTAINER_PREFIX)
                [ "$key" != "$line" ] || fail "Invalid configuration in $config_file"
                [ "$key" != TALLY_INSTALL_DIR ] || saved_install_dir="$value"
                export "$key=$value" ;;
        esac
    done < "$config_file"
fi
install_dir="${TALLY_INSTALL_DIR:-$HOME/.local/lib/godel-tally}"
data_dir="${TALLY_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/godel-tally}"
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
log "Remove application files from $install_dir"
log "Keep configuration and credentials in $config_dir"
log "Keep database data and certificates in $data_dir"
log 'Database packages and container volumes will be kept.'
units_removed=0
for name in server postgres clickhouse; do
    unit="$(service_file "$name")"
    [ -e "$unit" ] || continue
    log "Stop and remove the Tally $name user service"
    [ "$dry_run" = 0 ] || continue
    if [ "$os" = darwin ]; then
        label="gui/$(id -u)/ai.godel.tally.$name"
        if launchctl print "$label" >/dev/null 2>&1; then launchctl bootout "$label"; fi
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
    [ -f "$data_dir/containers/$engine-$name" ] || continue
    log "Stop the owned database container $name; keep its data"
    [ "$dry_run" = 0 ] || continue
    command -v "$engine" >/dev/null || fail "Start $engine and rerun uninstall to stop the owned database containers"
    if [ "$engine" = docker ]; then
        docker info >/dev/null || fail 'Start Docker and rerun uninstall'
        if docker inspect "$name" >/dev/null 2>&1 && [ "$(docker inspect --format '{{.State.Running}}' "$name")" = true ]; then docker stop "$name"; fi
    else
        running="$(container ls --quiet)" || fail 'Start Apple container and rerun uninstall'
        if printf '%s\n' "$running" | grep -Fxq "$name"; then container stop "$name"; fi
    fi
done
if [ "$dry_run" = 1 ]; then log 'Dry run complete; no changes made.'; exit 0; fi
if [ "$os" = linux ] && [ "$units_removed" = 1 ]; then systemctl --user daemon-reload; fi
# Remove only known application files, preserving anything an operator added.
for helper in runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do
    rm -f "$install_dir/scripts/$helper"
done
rm -f "$install_dir/tallyd" "$install_dir/tallyd.new" "$install_dir/tally.sh" "$install_dir/postgres.sh" "$install_dir/clickhouse.sh" "$install_dir/uninstall.sh"
rmdir "$install_dir/scripts" "$install_dir" 2>/dev/null || true
log 'Tally uninstalled. Rerun the installer to reuse the retained configuration and databases.'
