#!/usr/bin/env bash
set -euo pipefail
bundle="${1:?release directory required}"; shift
source "$bundle/scripts/runtime-common.sh"
source "$bundle/install.sh"
installer_init
installer_step 4 'Prepare the application' 'Check the message above, correct the setting, then rerun the same installation command.'
mode=; pg_mode=; ch_mode=; no_start=0; no_service=0; selected_port=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --port)
            [ "$#" -ge 2 ] && [[ "$2" =~ ^[1-9][0-9]{3,4}$ ]] && [ "$2" -ge 1024 ] && [ "$2" -le 65535 ] || fail '--port must be between 1024 and 65535'
            selected_port="$2"; shift 2 ;;
        --db|--postgres|--clickhouse)
            [ "$#" -ge 2 ] || fail "Missing value for $1"
            case "$2" in native|docker|apple|existing) ;; *) fail "Invalid database mode: $2" ;; esac
            case "$1" in --db) mode="$2" ;; --postgres) pg_mode="$2" ;; --clickhouse) ch_mode="$2" ;; esac
            shift 2 ;;
        --no-start) no_start=1; shift ;;
        --no-service) no_service=1; shift ;;
        *) fail "Unknown option: $1" ;;
    esac
done
[ "$(id -u)" != 0 ] || fail 'Run the installer as your normal user, without sudo.'
explicit_home="${TALLY_HOME:-}"
export TALLY_HOME="${TALLY_HOME:-$HOME/.godel-tally}"
legacy_config="${XDG_CONFIG_HOME:-$HOME/.config}/godel-tally"
if [ -z "$explicit_home" ] && [ -z "${TALLY_CONFIG_DIR:-}" ] && [ ! -f "$TALLY_HOME/config/tally.env" ] && [ -f "$legacy_config/tally.env" ]; then
    export TALLY_CONFIG_DIR="$legacy_config"
fi
export TALLY_CONFIG_DIR="${TALLY_CONFIG_DIR:-$TALLY_HOME/config}"
export TALLY_ENV_FILE="$TALLY_CONFIG_DIR/tally.env"
case "$TALLY_CONFIG_DIR" in /*) ;; *) fail 'Configuration path must be absolute' ;; esac
case "$TALLY_CONFIG_DIR" in *$'\n'*|*$'\r'*) fail 'Configuration path must not contain newlines' ;; esac
umask 077
mkdir -p "$TALLY_CONFIG_DIR"
lock_dir="$TALLY_CONFIG_DIR/.install-lock"
mkdir "$lock_dir" 2>/dev/null || fail "Another installation may be running. Wait for it to finish; after an interrupted installation, remove $lock_dir and retry."
install_lock_dir="$lock_dir"
load_env "$TALLY_ENV_FILE"
export TALLY_INSTALL_DIR="${TALLY_INSTALL_DIR:-$TALLY_HOME/app}"
export TALLY_DATA_DIR="${TALLY_DATA_DIR:-$TALLY_HOME/data}"
export TALLY_RUNTIME_DIR="${TALLY_RUNTIME_DIR:-$TALLY_HOME/runtime}"
for path in "$TALLY_INSTALL_DIR" "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR" "$TALLY_RUNTIME_DIR"; do
    case "$path" in /*) ;; *) fail 'Installation paths must be absolute' ;; esac
    case "$path" in *$'\n'*|*$'\r'*) fail 'Installation paths must not contain newlines' ;; esac
done
pg_mode="${pg_mode:-${mode:-${TALLY_POSTGRES_MODE:-native}}}"; ch_mode="${ch_mode:-${mode:-${TALLY_CLICKHOUSE_MODE:-native}}}"
if [ -f "$TALLY_ENV_FILE" ]; then
    # Reinstalling upgrades the application only. Database moves require an explicit migration.
    [ "$pg_mode" = "${TALLY_POSTGRES_MODE:-$pg_mode}" ] && [ "$ch_mode" = "${TALLY_CLICKHOUSE_MODE:-$ch_mode}" ] || fail 'Database modes differ from the saved configuration. Migrate data before changing tally.env.'
fi
export TALLY_POSTGRES_MODE="$pg_mode" TALLY_CLICKHOUSE_MODE="$ch_mode"
# The bundled executable handles certificate host checks on macOS's LibreSSL.
export TALLY_BINARY="$bundle/tallyd"
installer_prerequisites
install_hint='Check the selected database option, then rerun the same installation command.'
progress "PostgreSQL stores your settings; ClickHouse stores activity."
progress "Selected storage: PostgreSQL ($pg_mode), ClickHouse ($ch_mode)."
for db in postgres clickhouse; do
    if [ "$db" = postgres ]; then selected="$pg_mode"; else selected="$ch_mode"; fi
    case "$selected" in
        existing)
            if [ "$db" = postgres ]; then [ -n "${TALLY_POSTGRES_URL:-}" ] || fail 'Set TALLY_POSTGRES_URL for existing PostgreSQL'
            else [ -n "${TALLY_CLICKHOUSE_URL:-}" ] || fail 'Set TALLY_CLICKHOUSE_URL for existing ClickHouse'; fi ;;
        apple)
            [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ] || fail 'Apple container requires Apple silicon macOS'
            [ "$(sw_vers -productVersion | cut -d. -f1)" -ge 26 ] || fail 'Apple container requires macOS 26+'
            command -v container >/dev/null || fail 'Install Apple container from https://github.com/apple/container' ;;
        docker) command -v docker >/dev/null || fail 'Install Docker before selecting --db docker' ;;
    esac
done
if [ "$(uname -s)" = Linux ] && [ "$no_service" = 0 ]; then
    systemctl --user show-environment >/dev/null || fail 'A systemd user manager is required. Run from a login session, or use --no-service for manual startup.'
fi
if [ "$pg_mode" = native ] && [ -f "$TALLY_DATA_DIR/postgres/PG_VERSION" ]; then
    [ "$(cat "$TALLY_DATA_DIR/postgres/PG_VERSION")" = 18 ] || fail 'Your saved PostgreSQL data needs a major-version migration to PostgreSQL 18. Back up and migrate it before reinstalling; your data has not been changed.'
fi
# Older installs used independent database services. Check ownership before switching them.
legacy_units=()
for db in server postgres clickhouse; do
    if [ "$db" = server ]; then selected=native
    elif [ "$db" = postgres ]; then selected="$pg_mode"; else selected="$ch_mode"; fi
    [ "$selected" = native ] || continue
    if [ "$db" = server ]; then wrapper="$TALLY_INSTALL_DIR/tally.sh"; else wrapper="$TALLY_INSTALL_DIR/$db.sh"; fi
    if [ "$(uname -s)" = Darwin ]; then
        unit="$HOME/Library/LaunchAgents/ai.godel.tally.$db.plist"
        expected="<string>$(xml_escape "$wrapper")</string>"
    else
        unit="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/tally-$db.service"
        wrapper="${wrapper//\\/\\\\}"; wrapper="${wrapper//\"/\\\"}"; wrapper="${wrapper//%/%%}"; wrapper="${wrapper//\$/\$\$}"
        expected="ExecStart=/bin/bash \"$wrapper\""
    fi
    [ ! -e "$unit" ] || { [ ! -L "$unit" ] && grep -Fq "$expected" "$unit"; } || fail "Database service belongs to another installation: $unit"
    [ ! -e "$unit" ] || [ "$db" = server ] || legacy_units+=("$db")
done
install_hint='Download the release again. If the application check still fails, share this error and your operating system with your administrator.'
progress 'Checking that Tally and its browser console can run...'
"$bundle/tallyd" --check-ui >/dev/null
install_hint='Check that your user can write to the installation, configuration, and data folders shown above, then rerun the installer.'
progress "Installing application files in $TALLY_INSTALL_DIR"
umask 077
mkdir -p "$TALLY_INSTALL_DIR/scripts" "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR"
chmod 700 "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR"
# Copy atomically so a running Tally executable is never truncated during upgrade.
cp "$bundle/tallyd" "$TALLY_INSTALL_DIR/tallyd.new"
chmod 755 "$TALLY_INSTALL_DIR/tallyd.new"
mv "$TALLY_INSTALL_DIR/tallyd.new" "$TALLY_INSTALL_DIR/tallyd"
cp "$bundle/uninstall.sh" "$TALLY_INSTALL_DIR/uninstall.sh"
for helper in runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh download-databases.sh database-assets.tsv upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do cp "$bundle/scripts/$helper" "$TALLY_INSTALL_DIR/scripts/$helper"; done
export TALLY_SECRET_KEY="${TALLY_SECRET_KEY:-$(openssl rand -hex 32)}"
export TALLY_POSTGRES_PASSWORD="${TALLY_POSTGRES_PASSWORD:-$(openssl rand -hex 24)}"
if [ "$ch_mode" = existing ]; then export TALLY_CLICKHOUSE_PASSWORD="${TALLY_CLICKHOUSE_PASSWORD:-}"
else export TALLY_CLICKHOUSE_PASSWORD="${TALLY_CLICKHOUSE_PASSWORD:-$(openssl rand -hex 24)}"; fi
export TALLY_POSTGRES_PORT="${TALLY_POSTGRES_PORT:-5433}"
export TALLY_CLICKHOUSE_PORT="${TALLY_CLICKHOUSE_PORT:-8124}"
for port in "$TALLY_POSTGRES_PORT" "$TALLY_CLICKHOUSE_PORT"; do
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || fail 'Managed database ports must be between 1024 and 65535'
done
if [ "$pg_mode" != existing ]; then
    [[ "$TALLY_POSTGRES_PASSWORD" =~ ^[A-Za-z0-9._~-]+$ ]] || fail 'Managed PostgreSQL passwords must be URL-safe; use a generated password or existing mode with an encoded URL'
fi
export TALLY_CONTAINER_PREFIX="${TALLY_CONTAINER_PREFIX:-godel-tally}"
export TALLY_POSTGRES_URL="${TALLY_POSTGRES_URL:-postgres://tally:$TALLY_POSTGRES_PASSWORD@127.0.0.1:$TALLY_POSTGRES_PORT/tally}"
export TALLY_CLICKHOUSE_URL="${TALLY_CLICKHOUSE_URL:-http://127.0.0.1:$TALLY_CLICKHOUSE_PORT?user=tally}"
export TALLY_CLICKHOUSE_DATABASE="${TALLY_CLICKHOUSE_DATABASE:-tally}"
if [ "$pg_mode" = native ]; then
    [ "$TALLY_POSTGRES_URL" = "postgres://tally:$TALLY_POSTGRES_PASSWORD@127.0.0.1:$TALLY_POSTGRES_PORT/tally" ] || fail 'Private PostgreSQL uses the local Tally URL. Remove your TALLY_POSTGRES_URL override, or choose --postgres existing for an external server.'
fi
if [ "$ch_mode" = native ]; then
    [ "$TALLY_CLICKHOUSE_URL" = "http://127.0.0.1:$TALLY_CLICKHOUSE_PORT?user=tally" ] || fail 'Private ClickHouse uses the local Tally URL. Remove your TALLY_CLICKHOUSE_URL override, or choose --clickhouse existing for an external server.'
fi
export TALLY_URL="${TALLY_URL:-https://localhost:8443}"
export TALLY_HTTP_BIND="${TALLY_HTTP_BIND:-127.0.0.1:8443}"
if [ -n "$selected_port" ]; then
    # Keep the configured hostname/address, changing only the listening/public port.
    origin_pattern='^https://([A-Za-z0-9.-]+)(:[0-9]+)?/?$'
    [[ "$TALLY_URL" =~ $origin_pattern ]] || fail 'TALLY_URL must be an HTTPS origin such as https://tally.example.com:8443'
    export TALLY_URL="https://${BASH_REMATCH[1]}:$selected_port"
    [[ "$TALLY_HTTP_BIND" =~ ^(.+):[0-9]+$ ]] || fail 'TALLY_HTTP_BIND must include an address and port'
    export TALLY_HTTP_BIND="${BASH_REMATCH[1]}:$selected_port"
fi
export TALLY_UPGRADE_STATE_DIR="$TALLY_DATA_DIR/upgrade" TALLY_UPGRADE_WEB_ORIGIN="$TALLY_URL"
export TALLY_UPGRADE_TALLY_ROOT="$TALLY_INSTALL_DIR" TALLY_RUNTIME_MODE=combined TALLY_BINARY="$TALLY_INSTALL_DIR/tallyd"
export TALLY_MAINTENANCE_DIR="$TALLY_DATA_DIR/maintenance"
export TALLY_TLS_DIR="$TALLY_DATA_DIR/tls"
# Persist secrets before provisioning. A failed installation can be retried without rotating keys.
if [ ! -f "$TALLY_ENV_FILE" ]; then
    write_env TALLY_HOME TALLY_INSTALL_DIR TALLY_CONFIG_DIR TALLY_DATA_DIR TALLY_RUNTIME_DIR TALLY_SECRET_KEY \
      TALLY_POSTGRES_MODE TALLY_CLICKHOUSE_MODE TALLY_POSTGRES_PASSWORD TALLY_CLICKHOUSE_PASSWORD \
      TALLY_POSTGRES_PORT TALLY_CLICKHOUSE_PORT TALLY_CONTAINER_PREFIX TALLY_POSTGRES_URL \
      TALLY_CLICKHOUSE_URL TALLY_CLICKHOUSE_DATABASE TALLY_URL TALLY_HTTP_BIND TALLY_UPGRADE_STATE_DIR \
      TALLY_UPGRADE_WEB_ORIGIN TALLY_UPGRADE_TALLY_ROOT TALLY_RUNTIME_MODE TALLY_BINARY TALLY_MAINTENANCE_DIR TALLY_TLS_DIR > "$TALLY_ENV_FILE"
fi
# Preserve every other setting and secret when changing the application port.
if [ -n "$selected_port" ]; then
    updated="$(mktemp "$TALLY_CONFIG_DIR/.tally.env.XXXXXX")"
    while IFS= read -r line || [ -n "$line" ]; do
        case "${line%%=*}" in
            TALLY_URL|TALLY_HTTP_BIND|TALLY_UPGRADE_WEB_ORIGIN) write_env "${line%%=*}" ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$TALLY_ENV_FILE" > "$updated"
    for key in TALLY_URL TALLY_HTTP_BIND TALLY_UPGRADE_WEB_ORIGIN; do
        if ! grep -q "^$key=" "$updated"; then write_env "$key" >> "$updated"; fi
    done
    mv "$updated" "$TALLY_ENV_FILE"
fi
success 'Application files and settings are ready.'
installer_step 5 'Prepare your private databases' 'Check the download or database error above, then rerun the same installation command. Keep your saved settings and data folders.'
if [ "$pg_mode" = native ] || [ "$ch_mode" = native ]; then
    progress 'Downloading PostgreSQL and ClickHouse concurrently when needed. No system packages or sudo are used.'
    bash "$TALLY_INSTALL_DIR/scripts/download-databases.sh" || fail 'Tally could not download or verify its private databases. Read the database message above.'
fi
if [ "$pg_mode" = native ]; then
    export TALLY_PG_BIN="$(cat "$TALLY_RUNTIME_DIR/postgres.path")/bin"
    pg_banner="$("$TALLY_PG_BIN/postgres" --version)"
    [ "$(postgres_major_version "$pg_banner")" = 18 ] || fail 'The private PostgreSQL runtime must be version 18'
    progress "Using $pg_banner"
    progress 'Preparing the private PostgreSQL database...'
    if [ ! -f "$TALLY_DATA_DIR/postgres/PG_VERSION" ]; then
        password_file="$(mktemp "$TALLY_DATA_DIR/.pg-password.XXXXXX")"
        printf '%s\n' "$TALLY_POSTGRES_PASSWORD" > "$password_file"
        "$TALLY_PG_BIN/initdb" -D "$TALLY_DATA_DIR/postgres" -U tally --auth=scram-sha-256 --encoding=UTF8 --locale=C --pwfile="$password_file" || { rm -f "$password_file"; fail 'Could not prepare PostgreSQL. Check the error above.'; }
        rm -f "$password_file"
    fi
    success 'Settings storage is prepared. It will run with Tally.'
fi
if [ "$ch_mode" = native ]; then
    export TALLY_CLICKHOUSE_BIN="$(cat "$TALLY_RUNTIME_DIR/clickhouse.path")/bin/clickhouse"
    mkdir -p "$TALLY_DATA_DIR/clickhouse" "$TALLY_DATA_DIR/clickhouse/tmp" "$TALLY_DATA_DIR/clickhouse/user_files"
    if [ ! -f "$TALLY_CONFIG_DIR/clickhouse.xml" ]; then
        hash="$(printf '%s' "$TALLY_CLICKHOUSE_PASSWORD" | openssl dgst -sha256 | awk '{print $NF}')"
        cat > "$TALLY_CONFIG_DIR/clickhouse.xml" <<XML
<clickhouse>
<logger><level>warning</level><console>true</console></logger>
<listen_host>127.0.0.1</listen_host><http_port>$TALLY_CLICKHOUSE_PORT</http_port>
<path>$(xml_escape "$TALLY_DATA_DIR/clickhouse")/</path>
<tmp_path>$(xml_escape "$TALLY_DATA_DIR/clickhouse/tmp")/</tmp_path>
<user_files_path>$(xml_escape "$TALLY_DATA_DIR/clickhouse/user_files")/</user_files_path>
<users><tally><password_sha256_hex>$hash</password_sha256_hex><networks><ip>127.0.0.1</ip></networks><profile>default</profile><quota>default</quota><access_management>1</access_management></tally></users>
<profiles><default/></profiles><quotas><default/></quotas>
</clickhouse>
XML
    fi
    success 'Activity storage is prepared. It will run with Tally.'
fi
# Persist only runtime paths; retain all saved credentials and operator settings.
updated="$(mktemp "$TALLY_CONFIG_DIR/.tally.env.XXXXXX")"
while IFS= read -r line || [ -n "$line" ]; do
    case "${line%%=*}" in
        TALLY_RUNTIME_DIR|TALLY_PG_BIN|TALLY_CLICKHOUSE_BIN) write_env "${line%%=*}" ;;
        *) printf '%s\n' "$line" ;;
    esac
done < "$TALLY_ENV_FILE" > "$updated"
for key in TALLY_RUNTIME_DIR TALLY_PG_BIN TALLY_CLICKHOUSE_BIN; do
    if printenv "$key" >/dev/null && ! grep -q "^$key=" "$updated"; then write_env "$key" >> "$updated"; fi
done
mv "$updated" "$TALLY_ENV_FILE"
if [ "${#legacy_units[@]}" -gt 0 ]; then
    notice 'Switching this installation from separate database services to one supervised Tally service.'
    if [ "$(uname -s)" = Darwin ]; then launchctl bootout "gui/$(id -u)/ai.godel.tally.server" >/dev/null 2>&1 || true
    else systemctl --user stop tally-server.service; fi
    for db in "${legacy_units[@]}"; do
        if [ "$(uname -s)" = Darwin ]; then
            if launchctl print "gui/$(id -u)/ai.godel.tally.$db" >/dev/null 2>&1; then launchctl bootout "gui/$(id -u)/ai.godel.tally.$db"; fi
            rm -f "$HOME/Library/LaunchAgents/ai.godel.tally.$db.plist"
        else
            systemctl --user disable --now "tally-$db.service"
            rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/tally-$db.service"
        fi
    done
fi
# Container/existing modes retain their explicit external lifecycle; native mode is supervised.
bash "$TALLY_INSTALL_DIR/scripts/data-services.sh" up
installer_step 6 'Secure the browser connection' 'Check the certificate error above. If you supplied a certificate, check its hostname, expiry, and matching key; otherwise check your OpenSSL installation. Then rerun the installer.'
progress 'Preparing the certificate that protects your browser connection (HTTPS)...'
bash "$TALLY_INSTALL_DIR/scripts/ensure-tally-tls.sh"
export TALLY_TLS_CERT_FILE="${TALLY_TLS_CERT_FILE:-$TALLY_TLS_DIR/tally.crt}"
export TALLY_TLS_KEY_FILE="${TALLY_TLS_KEY_FILE:-$TALLY_TLS_DIR/tally.key}"
if ! grep -q '^TALLY_TLS_CERT_FILE=' "$TALLY_ENV_FILE"; then write_env TALLY_TLS_CERT_FILE TALLY_TLS_KEY_FILE >> "$TALLY_ENV_FILE"; fi
# Runtime dependencies need the same executable search path as this installation session.
{
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    printf 'export PATH=%q\nexport TALLY_ENV_FILE=%q\n' "$PATH" "$TALLY_ENV_FILE"
    printf 'source %q\nload_env "$TALLY_ENV_FILE"\n' "$TALLY_INSTALL_DIR/scripts/runtime-common.sh"
    printf '[ ! -f "$TALLY_MAINTENANCE_DIR/retired" ] || exit 0\n'
    printf 'bash %q up\n' "$TALLY_INSTALL_DIR/scripts/data-services.sh"
    printf 'cd %q\n' "$TALLY_DATA_DIR"
    if [ "$pg_mode" = native ] || [ "$ch_mode" = native ]; then
        printf 'exec %q supervise "$@"\n' "$TALLY_INSTALL_DIR/tallyd"
    else printf 'exec %q "$@"\n' "$TALLY_INSTALL_DIR/tallyd"; fi
} > "$TALLY_INSTALL_DIR/tally.sh"
chmod 700 "$TALLY_INSTALL_DIR/tally.sh"
success 'Secure browser connection configured.'
installer_step 7 'Finish setup' 'Check the startup error above, then rerun the installer.'
installer_service_hint server
if [ "$no_service" = 0 ]; then
    write_service server "$TALLY_INSTALL_DIR/tally.sh"
    if [ "$no_start" = 0 ]; then
        progress 'Starting Tally and checking that it can use your databases...'
        notice 'The first start prepares your data. This can take a few minutes.'
        if [ "$(uname -s)" = Darwin ]; then
            launchctl bootout "gui/$(id -u)/ai.godel.tally.server" >/dev/null 2>&1 || true
        else systemctl --user stop tally-server.service >/dev/null 2>&1 || true; fi
        start_service server
        ready=0
        for attempt in $(seq 1 120); do
            if curl --fail --silent --max-time 3 --cacert "$TALLY_TLS_CERT_FILE" --connect-to "::127.0.0.1:${TALLY_HTTP_BIND##*:}" "$TALLY_URL/api/v1/tally/health/ready" >/dev/null 2>&1; then ready=1; break; fi
            [ "$((attempt % 10))" != 0 ] || progress "Still waiting for Tally to be ready... (check $attempt of 120)"
            sleep 1
        done
        [ "$ready" = 1 ] || fail 'Tally was installed, but its browser console did not become ready.'
    fi
fi
printf '\n'
if [ "$no_service" = 1 ] || [ "$no_start" = 1 ]; then
    success 'Tally is installed. Startup was skipped as requested.'
    if [ "$no_service" = 1 ]; then notice 'You chose manual startup for this installation.'
    else notice 'Automatic startup is configured for your login session.'; fi
    printf '\n  Start Tally with:\n    bash %q\n' "$TALLY_INSTALL_DIR/tally.sh"
    printf '\n  After it starts, open: %s\n' "$TALLY_URL"
else
    success 'Tally is ready!'
    printf '\n  Open this address in your browser:\n\n'
    installer_line '32;1' '    ' "$TALLY_URL"
    printf '\n  On your first visit, create your administrator account.\n'
    notice 'Tally starts automatically when you log in.'
    if [ "$pg_mode" = native ] || [ "$ch_mode" = native ]; then notice 'Private databases start and stop with Tally.'; fi
fi
printf '\n  Settings: %s\n  Data:     %s\n' "$TALLY_ENV_FILE" "$TALLY_DATA_DIR"
