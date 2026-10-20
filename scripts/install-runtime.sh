#!/usr/bin/env bash
set -euo pipefail
bundle="${1:?release directory required}"; shift
source "$bundle/scripts/runtime-common.sh"
mode=; pg_mode=; ch_mode=; no_start=0; no_service=0
while [ "$#" -gt 0 ]; do
    case "$1" in
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
[ "$(id -u)" != 0 ] || fail 'Run the installer as your normal user; it uses sudo only for Linux packages.'
export TALLY_INSTALL_DIR="${TALLY_INSTALL_DIR:-$HOME/.local/lib/godel-tally}"
export TALLY_CONFIG_DIR="${TALLY_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/godel-tally}"
export TALLY_DATA_DIR="${TALLY_DATA_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/godel-tally}"
for path in "$TALLY_INSTALL_DIR" "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR"; do
    case "$path" in /*) ;; *) fail 'Installation paths must be absolute' ;; esac
    case "$path" in *$'\n'*|*$'\r'*) fail 'Installation paths must not contain newlines' ;; esac
done
export TALLY_ENV_FILE="$TALLY_CONFIG_DIR/tally.env"
load_env "$TALLY_ENV_FILE"
pg_mode="${pg_mode:-${mode:-${TALLY_POSTGRES_MODE:-native}}}"; ch_mode="${ch_mode:-${mode:-${TALLY_CLICKHOUSE_MODE:-native}}}"
if [ -f "$TALLY_ENV_FILE" ]; then
    # Reinstalling upgrades the application only. Database moves require an explicit migration.
    [ "$pg_mode" = "${TALLY_POSTGRES_MODE:-$pg_mode}" ] && [ "$ch_mode" = "${TALLY_CLICKHOUSE_MODE:-$ch_mode}" ] || fail 'Database modes differ from the saved configuration. Migrate data before changing tally.env.'
fi
export TALLY_POSTGRES_MODE="$pg_mode" TALLY_CLICKHOUSE_MODE="$ch_mode"
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
if [ "$(uname -s)" = Linux ] && { [ "$no_service" = 0 ] || [ "$pg_mode" = native ] || [ "$ch_mode" = native ]; }; then
    systemctl --user show-environment >/dev/null || fail 'A systemd user manager is required. Run from a login session, or use existing/container DBs with --no-service.'
fi
progress 'Checking the Tally executable and its web console...'
"$bundle/tallyd" --check-ui >/dev/null
progress "Installing application files in $TALLY_INSTALL_DIR"
umask 077
mkdir -p "$TALLY_INSTALL_DIR/scripts" "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR"
chmod 700 "$TALLY_CONFIG_DIR" "$TALLY_DATA_DIR"
# Copy atomically so a running Tally executable is never truncated during upgrade.
cp "$bundle/tallyd" "$TALLY_INSTALL_DIR/tallyd.new"
chmod 755 "$TALLY_INSTALL_DIR/tallyd.new"
mv "$TALLY_INSTALL_DIR/tallyd.new" "$TALLY_INSTALL_DIR/tallyd"
cp "$bundle/uninstall.sh" "$TALLY_INSTALL_DIR/uninstall.sh"
for helper in runtime-common.sh data-services.sh ensure-tally-tls.sh check-tls-host.sh upgrade-tally-to-gate.sh tally-source-db.py import-tally-users-to-gate.sql import-tally-registry-to-gate.sql validate-gate-registration.py; do cp "$bundle/scripts/$helper" "$TALLY_INSTALL_DIR/scripts/$helper"; done
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
export TALLY_URL="${TALLY_URL:-https://localhost:8443}"
export TALLY_HTTP_BIND="${TALLY_HTTP_BIND:-127.0.0.1:8443}"
export TALLY_UPGRADE_STATE_DIR="$TALLY_DATA_DIR/upgrade" TALLY_UPGRADE_WEB_ORIGIN="$TALLY_URL"
export TALLY_UPGRADE_TALLY_ROOT="$TALLY_INSTALL_DIR" TALLY_RUNTIME_MODE=combined TALLY_BINARY="$TALLY_INSTALL_DIR/tallyd"
export TALLY_MAINTENANCE_DIR="$TALLY_DATA_DIR/maintenance"
export TALLY_TLS_DIR="$TALLY_DATA_DIR/tls"
# Persist secrets before provisioning. A failed installation can be retried without rotating keys.
if [ ! -f "$TALLY_ENV_FILE" ]; then
    write_env TALLY_INSTALL_DIR TALLY_CONFIG_DIR TALLY_DATA_DIR TALLY_SECRET_KEY \
      TALLY_POSTGRES_MODE TALLY_CLICKHOUSE_MODE TALLY_POSTGRES_PASSWORD TALLY_CLICKHOUSE_PASSWORD \
      TALLY_POSTGRES_PORT TALLY_CLICKHOUSE_PORT TALLY_CONTAINER_PREFIX TALLY_POSTGRES_URL \
      TALLY_CLICKHOUSE_URL TALLY_CLICKHOUSE_DATABASE TALLY_URL TALLY_HTTP_BIND TALLY_UPGRADE_STATE_DIR \
      TALLY_UPGRADE_WEB_ORIGIN TALLY_UPGRADE_TALLY_ROOT TALLY_RUNTIME_MODE TALLY_BINARY TALLY_MAINTENANCE_DIR TALLY_TLS_DIR > "$TALLY_ENV_FILE"
fi
# Existing services and clusters are never rewritten; native mode creates private Tally instances.
if [ "$pg_mode" = native ] || [ "$ch_mode" = native ]; then
    progress "Preparing database packages (PostgreSQL: $pg_mode; ClickHouse: $ch_mode)..."
    if [ "$(uname -s)" = Darwin ]; then
        command -v brew >/dev/null || fail 'Install Homebrew from https://brew.sh, then rerun the installer'
        if [ "$pg_mode" = native ]; then
            brew list postgresql@18 >/dev/null 2>&1 || brew install postgresql@18
            pg_bin="$(brew --prefix postgresql@18)/bin"
        fi
        if [ "$ch_mode" = native ]; then
            brew list --cask clickhouse >/dev/null 2>&1 || brew install --cask clickhouse
            ch_bin="$(brew --prefix)/bin/clickhouse"
        fi
    elif command -v apt-get >/dev/null; then
        sudo apt-get update
        sudo apt-get install -y ca-certificates curl gnupg
        if [ "$pg_mode" = native ]; then
            release_file="${TALLY_OS_RELEASE_FILE:-/etc/os-release}"
            codename="$(. "$release_file"; printf '%s' "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}")"
            [[ "$codename" =~ ^[a-z]+$ ]] || fail 'Cannot determine the distribution codename for PostgreSQL packages'
            key="$(mktemp)"
            curl --proto '=https' -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o "$key"
            sudo install -m 644 "$key" /usr/share/keyrings/tally-postgresql.asc
            rm -f "$key"
            printf 'deb [signed-by=/usr/share/keyrings/tally-postgresql.asc] https://apt.postgresql.org/pub/repos/apt %s-pgdg main\n' "$codename" | sudo tee /etc/apt/sources.list.d/tally-postgresql.list >/dev/null
            sudo apt-get update
            sudo apt-get install -y postgresql-18 postgresql-client-18
        fi
        if [ "$ch_mode" = native ] && ! command -v clickhouse >/dev/null; then
            key="$(mktemp)"
            curl --proto '=https' -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | gpg --batch --dearmor > "$key"
            sudo install -m 644 "$key" /usr/share/keyrings/clickhouse-keyring.gpg
            rm -f "$key"
            printf 'deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=%s] https://packages.clickhouse.com/deb stable main\n' "$(dpkg --print-architecture)" | sudo tee /etc/apt/sources.list.d/clickhouse.list >/dev/null
            sudo apt-get update
            sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y clickhouse-server clickhouse-client
        fi
    elif command -v yum >/dev/null || command -v dnf >/dev/null; then
        if command -v dnf >/dev/null; then pm=dnf; else pm=yum; fi
        sudo "$pm" install -y ca-certificates curl
        if [ "$pg_mode" = native ]; then
            release_file="${TALLY_OS_RELEASE_FILE:-/etc/os-release}"
            os_id="$(. "$release_file"; printf '%s' "$ID")"
            os_version="$(. "$release_file"; printf '%s' "$VERSION_ID")"
            case "$os_id" in
                rhel|centos|rocky|almalinux|ol)
                    major="${os_version%%.*}"
                    [[ "$major" =~ ^[0-9]+$ ]] && [ "$major" -ge 8 ] || fail 'Native PostgreSQL requires Enterprise Linux 8 or newer'
                    sudo "$pm" install -y "https://download.postgresql.org/pub/repos/yum/reporpms/EL-$major-$(uname -m)/pgdg-redhat-repo-latest.noarch.rpm"
                    if [ "$major" -le 9 ]; then sudo "$pm" -qy module disable postgresql; fi
                    sudo "$pm" install -y postgresql18-server postgresql18
                    ;;
                fedora) sudo "$pm" install -y postgresql-server postgresql ;;
                *) fail 'Native RPM PostgreSQL supports RHEL, Rocky, AlmaLinux, CentOS, Oracle Linux or Fedora; use existing/docker elsewhere' ;;
            esac
        fi
        if [ "$ch_mode" = native ] && ! command -v clickhouse >/dev/null; then
            repo_file="$(mktemp)"
            curl --proto '=https' -fsSL https://packages.clickhouse.com/rpm/clickhouse.repo -o "$repo_file"
            sudo install -m 644 "$repo_file" /etc/yum.repos.d/clickhouse.repo
            rm -f "$repo_file"
            sudo "$pm" install -y clickhouse-server clickhouse-client
        fi
    else fail 'Native databases require Homebrew, apt, yum or dnf; select docker, apple or existing instead'; fi
fi
if [ "$pg_mode" = native ]; then
    if [ -z "${pg_bin:-}" ]; then
        if [ -x /usr/lib/postgresql/18/bin/initdb ]; then pg_bin=/usr/lib/postgresql/18/bin
        elif [ -x /usr/pgsql-18/bin/initdb ]; then pg_bin=/usr/pgsql-18/bin
        elif command -v initdb >/dev/null; then pg_bin="$(dirname "$(command -v initdb)")"
        elif command -v pg_config >/dev/null; then pg_bin="$(pg_config --bindir)"
        else
            pg_bin=
            for candidate in /usr/lib/postgresql/*/bin /usr/pgsql-*/bin; do
                [ ! -x "$candidate/initdb" ] || pg_bin="$candidate"
            done
        fi
    fi
    [ -x "$pg_bin/initdb" ] || fail 'PostgreSQL server binaries not found'
    pg_banner="$("$pg_bin/postgres" --version)"
    pg_major="$(postgres_major_version "$pg_banner")" || fail "Cannot read the PostgreSQL version: $pg_banner"
    [ "$pg_major" -ge 15 ] || fail "Tally requires PostgreSQL 15 or newer; found: $pg_banner"
    progress "Using $pg_banner"
    progress 'Preparing the private PostgreSQL database...'
    if [ ! -f "$TALLY_DATA_DIR/postgres/PG_VERSION" ]; then
        password_file="$(mktemp "$TALLY_DATA_DIR/.pg-password.XXXXXX")"
        printf '%s\n' "$TALLY_POSTGRES_PASSWORD" > "$password_file"
        "$pg_bin/initdb" -D "$TALLY_DATA_DIR/postgres" -U tally --auth=scram-sha-256 --pwfile="$password_file"
        rm -f "$password_file"
    fi
    {
        printf '#!/usr/bin/env bash\n'
        # LaunchAgents do not inherit the terminal locale. Match Homebrew's service
        # environment to prevent PostgreSQL's macOS multithreaded-startup failure.
        if [ "$(uname -s)" = Darwin ]; then printf 'export LC_ALL=en_US.UTF-8\n'; fi
        printf 'exec '; printf '%q ' "$pg_bin/postgres" -D "$TALLY_DATA_DIR/postgres" -h 127.0.0.1 -p "$TALLY_POSTGRES_PORT" -k ''; printf '\n'
    } > "$TALLY_INSTALL_DIR/postgres.sh"
    write_service postgres "$TALLY_INSTALL_DIR/postgres.sh"
    progress 'Starting the PostgreSQL user service...'
    start_service postgres
    ready=0
    for attempt in $(seq 1 60); do
        if "$pg_bin/pg_isready" -h 127.0.0.1 -p "$TALLY_POSTGRES_PORT" -U tally >/dev/null 2>&1; then ready=1; break; fi
        [ "$((attempt % 10))" != 0 ] || progress 'Waiting for PostgreSQL to become ready...'
        sleep 1
    done
    [ "$ready" = 1 ] || fail 'Private PostgreSQL instance did not become ready'
    export PGPASSWORD="$TALLY_POSTGRES_PASSWORD"
    if ! "$pg_bin/psql" -h 127.0.0.1 -p "$TALLY_POSTGRES_PORT" -U tally -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='tally'" | grep -qx 1; then
        "$pg_bin/createdb" -h 127.0.0.1 -p "$TALLY_POSTGRES_PORT" -U tally tally
    fi
    unset PGPASSWORD
fi
if [ "$ch_mode" = native ]; then
    progress 'Preparing the private ClickHouse database...'
    ch_bin="${ch_bin:-$(command -v clickhouse)}"
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
    { printf '#!/usr/bin/env bash\nexec '; printf '%q ' "$ch_bin" server "--config-file=$TALLY_CONFIG_DIR/clickhouse.xml"; printf '\n'; } > "$TALLY_INSTALL_DIR/clickhouse.sh"
    write_service clickhouse "$TALLY_INSTALL_DIR/clickhouse.sh"
    progress 'Starting the ClickHouse user service...'
    start_service clickhouse
    ready=0
    for attempt in $(seq 1 90); do
        if curl -fsS "http://127.0.0.1:$TALLY_CLICKHOUSE_PORT/ping" >/dev/null 2>&1; then ready=1; break; fi
        [ "$((attempt % 10))" != 0 ] || progress 'Waiting for ClickHouse to become ready...'
        sleep 1
    done
    [ "$ready" = 1 ] || fail 'Private ClickHouse instance did not become ready'
    [[ "$TALLY_CLICKHOUSE_DATABASE" =~ ^[A-Za-z0-9_]+$ ]] || fail 'Invalid ClickHouse database name'
    headers="$(mktemp "$TALLY_DATA_DIR/.clickhouse-headers.XXXXXX")"
    printf 'X-ClickHouse-User: tally\nX-ClickHouse-Key: %s\n' "$TALLY_CLICKHOUSE_PASSWORD" > "$headers"
    if ! curl -fsS --header "@$headers" --data-binary "CREATE DATABASE IF NOT EXISTS \`$TALLY_CLICKHOUSE_DATABASE\`" \
        "http://127.0.0.1:$TALLY_CLICKHOUSE_PORT/" >/dev/null; then
        rm -f "$headers"
        fail 'Could not create the Tally ClickHouse database'
    fi
    rm -f "$headers"
fi
progress "Checking database services (PostgreSQL: $pg_mode; ClickHouse: $ch_mode)..."
bash "$TALLY_INSTALL_DIR/scripts/data-services.sh" up
progress 'Preparing HTTPS for the web console...'
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
    printf 'cd %q\nexec %q "$@"\n' "$TALLY_DATA_DIR" "$TALLY_INSTALL_DIR/tallyd"
} > "$TALLY_INSTALL_DIR/tally.sh"
chmod 700 "$TALLY_INSTALL_DIR/tally.sh"
if [ "$no_service" = 0 ]; then
    write_service server "$TALLY_INSTALL_DIR/tally.sh"
    if [ "$no_start" = 0 ]; then
        progress "Starting Tally at $TALLY_URL; first-run database migrations may take a moment..."
        if [ "$(uname -s)" = Darwin ]; then
            launchctl bootout "gui/$(id -u)/ai.godel.tally.server" >/dev/null 2>&1 || true
        else systemctl --user stop tally-server.service >/dev/null 2>&1 || true; fi
        start_service server
        ready=0
        for attempt in $(seq 1 120); do
            if curl --fail --silent --max-time 3 --cacert "$TALLY_TLS_CERT_FILE" --connect-to "::127.0.0.1:${TALLY_HTTP_BIND##*:}" "$TALLY_URL/api/v1/tally/health/ready" >/dev/null 2>&1; then ready=1; break; fi
            [ "$((attempt % 10))" != 0 ] || progress 'Waiting for Tally to become ready...'
            sleep 1
        done
        [ "$ready" = 1 ] || fail 'Tally did not become ready; inspect the tally-server user service logs'
    fi
fi
printf 'Tally installed. URL: %s\nConfiguration: %s\nManual start: bash "%s/tally.sh"\n' "$TALLY_URL" "$TALLY_ENV_FILE" "$TALLY_INSTALL_DIR"
if [ "$no_service" = 1 ]; then
    printf 'No Tally application service was registered (--no-service).\n'
elif [ "$(uname -s)" = Linux ]; then
    printf 'Service: systemctl --user status tally-server\nFor boot before login, enable lingering: sudo loginctl enable-linger %s\n' "$(id -un)"
else printf 'Service: launchctl print gui/%s/ai.godel.tally.server (starts at login)\n' "$(id -u)"; fi
