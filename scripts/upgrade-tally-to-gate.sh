#!/usr/bin/env bash
# Standalone Tally -> fresh Docker-based Gate on the same host. Preparation leaves Tally
# read-only and Gate available for review. Cutover is a separate approved action.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [ -f "$root/scripts/runtime-common.sh" ]; then
    source "$root/scripts/runtime-common.sh"
    load_env "${TALLY_ENV_FILE:-$root/.env}"
fi
export TALLY_UPGRADE_STATE_DIR="${TALLY_UPGRADE_STATE_DIR:-${TALLY_DATA_DIR:-$root/.local}/upgrade}"
state_dir="$TALLY_UPGRADE_STATE_DIR/gate-upgrade"
maintenance_dir="${TALLY_MAINTENANCE_DIR:-$root/.local/tally-maintenance}"
mkdir -p "$state_dir"
chmod 700 "$state_dir"
phase="${1:-}"
shift || true

fail() { record failure_reason "$*"; progress "Stopped: $*"; echo "ERROR: $*" >&2; exit 1; }
record() { printf '%s' "$2" > "$state_dir/$1"; chmod 600 "$state_dir/$1"; }
progress() {
    printf '%s|%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$state_dir/progress.log"
    chmod 600 "$state_dir/progress.log"
}
trap 'if [ ! -f "$state_dir/failure_reason" ]; then record failure_reason "A host command failed during the most recent upgrade activity. Review the attempt log."; fi' ERR
trap 'if [ "$?" != 0 ]; then case "$phase:$(cat "$state_dir/status" 2>/dev/null || true)" in prepare:preflight|prepare:staging|prepare:copying) record status failed ;; cutover:cutting_over) record status cutover_failed ;; esac; fi' EXIT
read_record() { cat "$state_dir/$1"; }
enable_read_only() { mkdir -p "$maintenance_dir"; : > "$maintenance_dir/read-only"; }
disable_read_only() { rm -f "$maintenance_dir/read-only"; }
compose_tally() {
    if [ "$(read_record mode)" = dev ]; then
        docker compose -f "$root/docker-compose.yml" -f "$root/docker-compose.dev.yml" "$@"
    else
        docker compose -f "$root/docker-compose.yml" "$@"
    fi
}
compose_gate() { (cd "$(read_record gate_dir)" && docker compose "$@"); }
combined_runtime() {
    case "$(cat "$state_dir/mode" 2>/dev/null || printf '%s' "${TALLY_RUNTIME_MODE:-legacy}")" in combined*) return 0 ;; *) return 1 ;; esac
}
tally_query() {
    if combined_runtime; then python3 "$root/scripts/tally-source-db.py" query "$1"
    else compose_tally exec -T postgres psql -U tally -d tally -Atc "$1"; fi
}
tally_dump() {
    if combined_runtime; then python3 "$root/scripts/tally-source-db.py" dump
    else compose_tally exec -T postgres pg_dump -Fc --no-owner -U tally tally; fi
}
pause_combined_writers() {
    local attempt scans
    # The binary acknowledges only after its current connector batch and API mutations finish.
    for attempt in $(seq 1 180); do
        if [ -f "$maintenance_dir/writers-drained" ]; then
            scans="$(tally_query "SELECT count(*) FROM scan_jobs WHERE status IN ('planned', 'running', 'cancel_requested')")"
            [ "$scans" != 0 ] || return 0
        fi
        sleep 1
    done
    fail "Tally writers did not drain; let active scans finish and retry the upgrade"
}
pause_tally_http() {
    if combined_runtime; then : > "$maintenance_dir/http-paused"
    else compose_tally stop router; fi
}
resume_tally_http() {
    if combined_runtime; then rm -f "$maintenance_dir/http-paused"; verify_tally_http
    else compose_tally up -d --no-deps --wait --wait-timeout 120 router; fi
}
verify_tally_http() {
    local attempt port cert="${TALLY_TLS_CERT_FILE:-$root/.local/tls/tally.crt}" options=()
    port="${TALLY_URL##*:}"; [[ "$port" =~ ^[0-9]+$ ]] || port=443
    options=(-fsS --noproxy '*' --max-time 2 --connect-to "::127.0.0.1:$port")
    if [ -f "$cert" ]; then options+=(--cacert "$cert"); fi
    for attempt in $(seq 1 60); do
        if curl "${options[@]}" \
            "$TALLY_URL/api/v1/tally/health/ready" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    return 1
}

sha256_file() {
    if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d ' ' -f 1
    else shasum -a 256 "$1" | cut -d ' ' -f 1; fi
}
verify_url() {
    local authority host port
    authority="${1#https://}"
    host="${authority%%:*}"
    port=443
    [ "$authority" = "$host" ] || port="${authority##*:}"
    if [ "${3:-}" = public ]; then
        curl -fsS --noproxy '*' --max-time 15 --resolve "$host:$port:127.0.0.1" "$1/api/v1/health" >/dev/null
    else
        curl -fsS --noproxy '*' --max-time 15 --resolve "$host:$port:127.0.0.1" "$1/api/v1/health" >/dev/null 2>&1 \
          || curl -fsS --noproxy '*' --max-time 15 --resolve "$host:$port:127.0.0.1" \
               --cacert "$2" "$1/api/v1/health" >/dev/null
    fi
}
port_available() {
    python3 - "$1" <<'PY'
import socket
import sys
with socket.socket() as listener:
    listener.bind(("0.0.0.0", int(sys.argv[1])))
PY
}
select_port() {
    local port
    for port in "$@"; do
        if port_available "$port" 2>/dev/null; then printf '%s' "$port"; return 0; fi
    done
    return 1
}
tally_router_publishes_port() {
    local container
    if combined_runtime; then
        local bind="${TALLY_HTTP_BIND:-127.0.0.1:2357}" port
        case "$(read_record mode)" in
            combined-dev) bind="${TALLY_DEV_BIND:-127.0.0.1:8080}" ;;
            combined-compose) bind="${TALLY_PUBLISH_BIND:-127.0.0.1:2357}" ;;
        esac
        port="${bind##*:}"
        [ "$port" = "$1" ] && [ -f "$maintenance_dir/writers-drained" ]
        return
    fi
    container="$(compose_tally ps -q router)" || return 1
    [ -n "$container" ] || return 1
    docker port "$container" | awk -F: -v port="$1" '
        $NF == port { found = 1 }
        END { exit !found }
    '
}
wait_for_port_release() {
    local port="$1" attempt deadline=$((SECONDS + 120))
    for attempt in $(seq 1 60); do
        port_available "$port" 2>/dev/null && return 0
        [ "$SECONDS" -lt "$deadline" ] || break
        sleep 2
    done
    fail "HTTPS port $port did not become available; Tally application services were retained"
}
start_gate_router() {
    local attempt container state output remaining wait_timeout deadline=$((SECONDS + 120))
    for attempt in $(seq 0 60); do
        remaining=$((deadline - SECONDS))
        [ "$remaining" -gt 0 ] || return 1
        wait_timeout=45
        [ "$remaining" -ge 45 ] || wait_timeout="$remaining"
        if [ "$attempt" = 0 ]; then
            if output="$(compose_gate up -d --no-deps --force-recreate --wait --wait-timeout "$wait_timeout" router 2>&1)"; then printf '%s\n' "$output"; return 0; fi
        else
            if output="$(compose_gate up -d --no-deps --wait --wait-timeout "$wait_timeout" router 2>&1)"; then printf '%s\n' "$output"; return 0; fi
        fi
        printf '%s\n' "$output" >&2
        container="$(compose_gate ps -a -q router)" || return 1
        [ -n "$container" ] || return 1
        state="$(docker inspect --format '{{.State.Status}}|{{.State.Error}}' "$container")" || return 1
        state="$state|$output"
        # A failed bind leaves a Created container. Retry starting that same
        # container while Docker releases the previous listener; do not recreate it.
        case "$state" in
            created*'ports are not available'*|created*'address already in use'*) ;;
            *) return 1 ;;
        esac
        [ "$attempt" -lt 60 ] || return 1
        [ "$SECONDS" -lt "$deadline" ] || return 1
        [ "$attempt" != 0 ] || progress "Waiting for Docker to release the Gate router ports"
        sleep 2
    done
}
set_gate_env() {
    local file temp
    file="$(read_record gate_dir)/.env"
    temp="$(mktemp "${file}.XXXXXX")"
    awk -v key="$1" -v value="$2" '
        index($0, key "=") == 1 { print key "=" value; found = 1; next }
        { print }
        END { if (!found) print key "=" value }
    ' "$file" > "$temp"
    chmod 600 "$temp"
    mv "$temp" "$file"
}
validate_final_tls() {
    local cert="$1" key="$2" host="$3" cert_public key_public
    [ -r "$cert" ] && [ -r "$key" ] || fail "production TLS certificate and private key must be readable"
    cert_public="$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256_file /dev/stdin)" \
        || fail "could not inspect production TLS certificate"
    key_public="$(openssl pkey -in "$key" -passin pass: -pubout -outform DER 2>/dev/null | sha256_file /dev/stdin)" \
        || fail "could not inspect production TLS private key"
    [ "$cert_public" = "$key_public" ] || fail "production TLS certificate and private key do not match"
    bash "$root/scripts/check-tls-host.sh" "$cert" "$host" || fail "TLS certificate does not cover $host"
    openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1 || fail "production TLS certificate has expired"
    local issuer subject
    issuer="$(openssl x509 -in "$cert" -noout -issuer | sed 's/^issuer= *//')"
    subject="$(openssl x509 -in "$cert" -noout -subject | sed 's/^subject= *//')"
    [ "$issuer" != "$subject" ] || fail "production TLS certificate is self-signed; provide a trusted certificate before cutover"
}
stage_certificate() {
    local host="$1" config="$state_dir/staging-openssl.cnf" san="DNS:$1"
    [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && san="IP:$host"
    cat > "$config" <<EOF
[req]
distinguished_name = subject
x509_extensions = extensions
prompt = no
[subject]
CN = $host
[extensions]
subjectAltName = $san
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
    openssl req -x509 -newkey rsa:2048 -nodes -days 14 \
        -keyout "$state_dir/staging.key" -out "$state_dir/staging.crt" \
        -config "$config" >/dev/null 2>&1 || fail "could not generate Gate review certificate"
    chmod 600 "$state_dir/staging.key" "$state_dir/staging.crt" "$config"
}
tally_count() { tally_query "SELECT count(*) FROM $1"; }
gate_count() { compose_gate exec -T postgres psql -U ggate -d ggate -Atc "SELECT count(*) FROM $1"; }
check_migration_versions() {
    local source_head gate_head warning
    source_head="$(tally_query 'SELECT max(version) FROM _sqlx_migrations WHERE success')"
    gate_head="$(cat "$(read_record gate_dir)/console-config/tally-schema-head.txt" 2>/dev/null || true)"
    record source_schema_head "$source_head"
    record gate_schema_head "$gate_head"
    rm -f "$state_dir/migration_warning"
    if [[ ! "$source_head" =~ ^[0-9]+$ ]] || [[ ! "$gate_head" =~ ^[0-9]+$ ]]; then
        warning="PostgreSQL migration versions could not be compared; continuing with best-effort data transfer."
    elif [ "$source_head" = "$gate_head" ]; then
        echo "Tally schema version $source_head matches the Gate release"
        progress "Tally schema matches the Gate release"
        return 0
    else
        warning="PostgreSQL migrations differ (Tally $source_head, Gate $gate_head); continuing with best-effort data transfer."
    fi
    record migration_warning "$warning"
    echo "WARNING: $warning"
    progress "$warning"
}
prepare_imported_migration_ledger() {
    local source_head gate_head
    source_head="$(read_record source_schema_head)"
    gate_head="$(read_record gate_schema_head)"
    # Older Tally dumps are upgraded by Gate's normal migrator. For newer dumps,
    # SQLx rejects versions absent from Gate's bundle even if its schema works.
    # Archive only those successful entries in the restored Gate copy. Never
    # clear the ledger or change checksums, tables, or the source Tally database.
    [[ "$source_head" =~ ^[0-9]+$ ]] && [[ "$gate_head" =~ ^[0-9]+$ ]] || return 0
    [ "$source_head" -gt "$gate_head" ] || return 0
    progress "Preserving newer Tally migration history in the Gate copy"
    compose_gate exec -T postgres psql -U ggate -d ggate -v ON_ERROR_STOP=1 -q <<SQL
BEGIN;
LOCK TABLE _sqlx_migrations IN ACCESS EXCLUSIVE MODE;
CREATE TABLE IF NOT EXISTS tally_upgrade_newer_migrations
    (LIKE _sqlx_migrations INCLUDING ALL);
WITH newer AS (
    DELETE FROM _sqlx_migrations WHERE version > $gate_head AND success RETURNING *
)
INSERT INTO tally_upgrade_newer_migrations SELECT * FROM newer;
COMMIT;
SQL
    progress "Newer Tally tables and data retained; Gate will validate its supported migrations"
}
import_users() {
    local unsupported
    unsupported="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc '
        SELECT count(*) FROM tally_auth_users WHERE password_hash IS NULL')"
    [ "$unsupported" = 0 ] || fail "A Tally account has no password. Send it a password link from Users, then retry the upgrade"
    if ! (umask 077; compose_gate exec -T postgres psql -U ggate -d ggate \
        -v ON_ERROR_STOP=1 -q < "$root/scripts/import-tally-users-to-gate.sql" \
        > "$state_dir/user-import.log" 2>&1); then
        fail "Gate user import failed; inspect $state_dir/user-import.log on the host"
    fi
}
verify_users() {
    local source target mismatched receipt
    source="$(gate_count tally_auth_users)"
    target="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc '
        SELECT count(*) FROM tally_auth_users a JOIN users g ON g.id = a.user_id')"
    mismatched="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc '
        SELECT count(*) FROM tally_auth_users a
        LEFT JOIN users g ON g.id = a.user_id
        LEFT JOIN roles r ON r.id = g.role_id
        WHERE g.id IS NULL OR g.email IS DISTINCT FROM a.email
           OR g.password_hash IS DISTINCT FROM a.password_hash
           OR g.is_active IS DISTINCT FROM (a.disabled_at IS NULL)
           OR r.name IS DISTINCT FROM
              (CASE a.role WHEN '\''admin'\'' THEN '\''super_admin'\'' ELSE '\''member'\'' END)')"
    [ "$source" = "$target" ] && [ "$mismatched" = 0 ] \
        || fail "Gate IAM user verification failed: $target of $source accounts present, $mismatched mismatched"
    receipt="$state_dir/verification.txt"
    if [ -f "$receipt" ]; then
        grep -v '^tally_users=' "$receipt" > "$receipt.tmp" || true
        mv "$receipt.tmp" "$receipt"
    fi
    printf 'tally_users=%s\n' "$source" >> "$receipt"
    chmod 600 "$receipt"
    echo "Verified Gate IAM accounts: $source users"
}
reconcile_registry() {
    if ! (umask 077; compose_gate exec -T postgres psql -U ggate -d ggate \
        -v ON_ERROR_STOP=1 -q < "$root/scripts/import-tally-registry-to-gate.sql" \
        > "$state_dir/registry-import.log" 2>&1); then
        fail "Gate registry reconciliation failed; inspect $state_dir/registry-import.log on the host"
    fi
}
verify_registry() {
    local table source_rows gate_rows missing source_count cursor_decision cursor_match
    for table in ai_providers ai_models; do
        source_rows="$(tally_query \
            "SELECT key, COALESCE(sanctioned::text, 'null') FROM $table")"
        gate_rows="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc \
            "SELECT key, COALESCE(sanctioned::text, 'null') FROM $table")"
        missing="$(LC_ALL=C comm -23 \
            <(printf '%s\n' "$source_rows" | LC_ALL=C sort) \
            <(printf '%s\n' "$gate_rows" | LC_ALL=C sort) | wc -l | tr -d ' ')"
        [ "$missing" = 0 ] || fail "$table registry decisions differ between Tally and Gate ($missing missing or changed)"
        source_count="$(tally_count "$table")"
        printf '%s=%s\n' "$table" "$source_count" >> "$state_dir/verification.txt"
        echo "Verified $table registry decisions: $source_count entries"
    done
    cursor_decision="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc \
        "SELECT COALESCE(sanctioned::text, 'null') FROM ai_providers WHERE key = 'cursor'")"
    if [ "$cursor_decision" != null ]; then
        cursor_match="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atc \
            "SELECT count(*) FROM ai_providers p JOIN ai_agent_registry a ON a.agent_key = p.key WHERE p.key = 'cursor' AND a.sanctioned IS NOT DISTINCT FROM p.sanctioned")"
        [ "$cursor_match" = 1 ] || fail "Gate Cursor coding-agent decision does not match the Tally provider decision"
        printf 'cursor_agent_decision=verified\n' >> "$state_dir/verification.txt"
    fi
}
verify_counts() {
    local table source target key missing keys_dir
    keys_dir="$(mktemp -d "$state_dir/verification-keys.XXXXXX")" \
        || fail "could not create the data verification workspace"
    : > "$state_dir/verification.txt"
    if [ -f "$state_dir/source_schema_head" ]; then
        printf 'tally_schema_head=%s\ngate_schema_head=%s\n' \
            "$(read_record source_schema_head)" "$(read_record gate_schema_head)" >> "$state_dir/verification.txt"
    fi
    for table in installations connector_states connector_jobs connector_runs ingestion_batches findings finding_observations endpoint_hosts endpoint_users audit_log; do
        source="$(tally_count "$table")"
        target="$(gate_count "$table")"
        # Gate's worker is already running during preparation and can add runs,
        # audit records and findings. Verify the copied identities in both phases.
        case "$table" in
            installations) key=installation_id ;;
            connector_states) key=connector_instance_id ;;
            connector_jobs) key=job_id ;;
            connector_runs) key=run_id ;;
            ingestion_batches) key=batch_id ;;
            findings) key=finding_id ;;
            finding_observations) key="observation_id::text || ':' || finding_id::text" ;;
            endpoint_hosts) key=endpoint_host_id ;;
            endpoint_users) key=endpoint_user_id ;;
            audit_log) key=audit_id ;;
        esac
        # Process substitutions do not propagate a failed database query. Stage
        # each key stream separately so an unavailable database cannot pass.
        if ! tally_query "SELECT ($key)::text FROM $table" \
            | LC_ALL=C sort > "$keys_dir/tally"; then
            rm -rf -- "$keys_dir"
            fail "could not read Tally $table primary keys"
        fi
        if ! compose_gate exec -T postgres psql -U ggate -d ggate -Atc "SELECT ($key)::text FROM $table" \
            | LC_ALL=C sort > "$keys_dir/gate"; then
            rm -rf -- "$keys_dir"
            fail "could not read Gate $table primary keys"
        fi
        missing="$(LC_ALL=C comm -23 "$keys_dir/tally" "$keys_dir/gate" | wc -l | tr -d ' ')"
        if [ "$missing" != 0 ]; then
            rm -rf -- "$keys_dir"
            fail "$table is missing $missing copied Tally rows in Gate"
        fi
        if [ "$target" -lt "$source" ]; then
            rm -rf -- "$keys_dir"
            fail "$table row count is lower in Gate: Tally $source, Gate $target"
        fi
        echo "Verified $table: $source Tally rows present in $target Gate rows"
        printf '%s=%s\n' "$table" "$source" >> "$state_dir/verification.txt"
    done
    rm -rf -- "$keys_dir"
    source="$(tally_count tally_auth_users)"
    target="$(gate_count tally_auth_users)"
    [ "$source" = "$target" ] || fail "Tally authentication user count differs: Tally $source, Gate $target"
    verify_users
    verify_registry
}

pre_switch_cutover_failure() {
    [ "$(read_record status)" = cutover_failed ] || return 1
    [ -f "$state_dir/writers-paused" ] || return 1
    [ ! -f "$state_dir/final_url" ] || return 1
    if [ -f "$state_dir/cutover_stage" ]; then
        [ "$(read_record cutover_stage)" = preflight ]
    else
        grep -q 'row count differs' "$state_dir/failure_reason" 2>/dev/null
    fi
}
pause_dev_processes() {
    local name label launcher pid executable found
    [ -r "$TALLY_UPGRADE_STATE_DIR/dev-processes" ] || fail "make dev process receipt is missing"
    for name in tally-collector; do
        label=COLLECTOR_PID
        launcher="$(sed -n "s/^${label}=//p" "$TALLY_UPGRADE_STATE_DIR/dev-processes")"
        [ -n "$launcher" ] && kill -0 "$launcher" 2>/dev/null \
            || fail "make dev $name launcher is not running"
        found=0
        for pid in $(descendants "$launcher"); do
            executable="$(ps -p "$pid" -o comm= 2>/dev/null || true)"
            if [ "${executable##*/}" = "$name" ]; then
                kill -STOP "$pid"
                printf '%s\n' "$pid" >> "$state_dir/paused-pids"
                found=1
            fi
        done
        [ "$found" = 1 ] || fail "make dev $name process was not found under its launcher"
        # cargo watch would otherwise restart a paused worker after a source edit.
        kill -STOP "$launcher"
        printf '%s\n' "$launcher" >> "$state_dir/paused-pids"
    done
}
descendants() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null || true); do
        descendants "$child"
        printf '%s\n' "$child"
    done
}
resume_dev_processes() {
    if [ -f "$state_dir/paused-pids" ]; then
        while IFS= read -r pid; do kill -CONT "$pid" 2>/dev/null || true; done < "$state_dir/paused-pids"
        rm -f "$state_dir/paused-pids"
    fi
}
resume_tally() {
    [ -f "$state_dir/writers-paused" ] || return 0
    if [ -f "$state_dir/paused-pids" ]; then resume_dev_processes; fi
    if [ "$(read_record mode)" = compose ]; then
        compose_tally up -d tallyd collector || true
    fi
    disable_read_only
    rm -f "$maintenance_dir/writers-drained"
    rm -f "$state_dir/writers-paused"
}
kill_tree() {
    local child
    for child in $(pgrep -P "$1" 2>/dev/null || true); do kill_tree "$child"; done
    kill -TERM "$1" 2>/dev/null || true
}
restore_cutover_review() {
    local exit_code="$1" restored=1 gate_certs backup
    [ "$exit_code" != 0 ] || return 0
    trap - ERR EXIT
    set +e
    backup="$state_dir/cutover-review-backup"
    gate_certs="$(read_record gate_dir)/certs"
    progress "The switch paused; restoring the Gate review installation and Tally router"
    compose_gate stop router || restored=0
    cp "$backup/gate.env" "$(read_record gate_dir)/.env" || restored=0
    cp "$backup/console.crt" "$gate_certs/console.crt" || restored=0
    cp "$backup/console.key" "$gate_certs/console.key" || restored=0
    chmod 600 "$(read_record gate_dir)/.env" "$gate_certs/console.key" || restored=0
    chmod 644 "$gate_certs/console.crt" || restored=0
    if [ -f "$backup/.self-signed" ]; then
        cp "$backup/.self-signed" "$gate_certs/.self-signed" || restored=0
    else
        rm -f "$gate_certs/.self-signed"
    fi
    compose_gate up -d --no-deps --force-recreate --wait --wait-timeout 120 worker || restored=0
    compose_gate up -d --no-deps --force-recreate --wait --wait-timeout 120 api || restored=0
    start_gate_router || restored=0
    verify_url "$(read_record temp_url)" "$(read_record staging_cert)" || restored=0
    if [ "${tally_router_paused:-0}" = 1 ]; then
        resume_tally_http || restored=0
    fi
    # Never resume Tally writers here. Gate might have received writes once
    # activation began; such failures still require explicit recovery.
    if [ "$restored" = 1 ] && [ "${gate_activated:-0}" = 0 ]; then
        record cutover_stage preflight
        progress "Gate review and Tally access restored; Tally remains read-only and the switch can be retried"
    elif [ "$restored" = 1 ]; then
        record cutover_stage activation_failed
        progress "Tally access restored in read-only mode; Gate activation needs review before another switch"
    else
        record cutover_stage recovery_failed
        progress "Automatic router recovery needs attention; Tally application services and both data volumes are retained"
    fi
    record status cutover_failed
}

if [ "$phase" = prepare ]; then
    progress "Checking Tally, Docker, and the selected Gate directory"
    [ "${1:-}" = "--console-url" ] || fail "expected --console-url URL --registration-key-file PATH --gate-dir PATH"
    temp_url="${2:-}"; shift 2
    [ "${1:-}" = "--registration-key-file" ] || fail "expected --registration-key-file"; registration_file="${2:-}"; shift 2
    [ "${1:-}" = "--gate-dir" ] || fail "expected --gate-dir"; gate_dir="${2:-}"; shift 2
    pinned_version=""; pinned_checksum=""
    if [ "${1:-}" = "--release-version" ]; then pinned_version="${2:-}"; shift 2; fi
    if [ "${1:-}" = "--installer-sha256" ]; then pinned_checksum="${2:-}"; shift 2; fi
    [ $# -eq 0 ] || fail "unexpected prepare arguments"
    [[ "$temp_url" =~ ^https://[A-Za-z0-9.-]+:[0-9]+$ ]] || fail "invalid Gate review URL"
    [ -r "$registration_file" ] || fail "registration key file must be readable"
    cert_host="${temp_url#https://}"
    cert_host="${cert_host%%:*}"
    if [ -e "$gate_dir" ]; then
        [ -d "$gate_dir" ] && [ -z "$(ls -A "$gate_dir")" ] \
          || fail "Gate install directory must not contain files; a fresh target is required"
    fi
    [ ! -f "$state_dir/status" ] || fail "an upgrade job already exists"
    command -v docker >/dev/null || fail "Docker is required for Gate, including upgrades from native or Apple-container Tally"
    docker info >/dev/null 2>&1 || fail "Start Docker before upgrading to Gate"
    docker compose version >/dev/null || fail "Docker Compose is required for Gate"
    command -v curl >/dev/null || fail "curl is required"
    command -v python3 >/dev/null || fail "Python 3 is required to select an available Gate review port"
    command -v openssl >/dev/null || fail "OpenSSL is required to generate the Gate review certificate"
    requested_port="${temp_url##*:}"
    stage_port="$(select_port "$requested_port" 8443 9443 10443 11443 12443)" \
        || fail "no Gate review HTTPS port is available (8443, 9443, 10443, 11443, 12443)"
    stage_http_port="$(select_port 8081 9081 10081 11081)" || fail "no Gate review HTTP port is available"
    import_pg_port="$(select_port 55432 55433 55434)" || fail "no Gate import database port is available"
    temp_url="https://$cert_host:$stage_port"
    umask 077
    stage_certificate "$cert_host"
    cert="$state_dir/staging.crt"; key="$state_dir/staging.key"

    if combined_runtime; then
        mode="${TALLY_RUNTIME_MODE:-combined}"
    elif [ -n "$(docker compose -f "$root/docker-compose.yml" ps --status running -q tallyd)" ]; then
        mode=compose
    elif [ -f "$TALLY_UPGRADE_STATE_DIR/dev-processes" ]; then
        mode=dev
    else
        fail "Tally must be running under make dev or make up on this Docker host"
    fi
    record mode "$mode"; record gate_dir "$gate_dir"; record temp_url "$temp_url"
    record stage_http_port "$stage_http_port"
    record staging_cert "$cert"
    record status preflight
    umask 077
    if combined_runtime; then
        [ -n "${TALLY_SECRET_KEY:-}" ] || fail "TALLY_SECRET_KEY is required to preserve connector credentials"
        write_env TALLY_SECRET_KEY > "$state_dir/tally.env"
        tally_query 'SELECT 1' >/dev/null || fail "Tally source PostgreSQL is not available"
        record tally_storage "${TALLY_POSTGRES_MODE:-existing}"
    else
        [ -r "$root/.env" ] || fail "Tally .env is required to preserve connector credentials"
        cp "$root/.env" "$state_dir/tally.env"
        tally_container="$(compose_tally ps -q postgres)"
        [ -n "$tally_container" ] || fail "Tally PostgreSQL is not running"
        tally_volume="$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/var/lib/postgresql"}}{{.Name}}{{end}}{{end}}' "$tally_container")"
        [ -n "$tally_volume" ] || fail "Tally PostgreSQL volume could not be identified"
        record tally_volume "$tally_volume"
    fi
    manifest="$state_dir/latest.json"
    installer="$state_dir/install-console.sh"
    if [ -n "$pinned_version" ] && [ -n "$pinned_checksum" ]; then
        version="$pinned_version"; checksum="$pinned_checksum"
    else
        curl -fsSL --max-time 30 https://dl.godel-labs.ai/godel-gate/console/latest/manifest.json -o "$manifest"
        version="$(sed -n 's/.*"version":"\([0-9][0-9.]*\)".*/\1/p' "$manifest")"
        checksum="$(sed -n 's/.*"installer_sha256":"\([a-f0-9]*\)".*/\1/p' "$manifest")"
    fi
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "latest Console version is invalid"
    [[ "$checksum" =~ ^[a-f0-9]{64}$ ]] || fail "latest Console checksum is invalid"
    curl -fsSL --max-time 60 "https://dl.godel-labs.ai/godel-gate/console/$version/install-console.sh" -o "$installer"
    [ "$(sha256_file "$installer")" = "$checksum" ] || fail "Console installer checksum mismatch"
    record version "$version"
    echo "Using verified Gate Console installer $version"
    progress "Verified Gate Console installer $version"

    # Compile the credential transformer before pausing Tally writes.
    if combined_runtime; then
        rekey=("${TALLY_BINARY:-$root/tallyd}" rekey-for-gate)
        [ -x "${rekey[0]}" ] || fail "Set TALLY_BINARY to the host Tally binary for Gate credential migration"
    else
        (cd "$root" && cargo build -q -p tallyd --bin tally-rekey-for-gate)
        rekey=("$root/target/debug/tally-rekey-for-gate")
    fi
    record status staging
    progress "Starting the Gate import database"
    # The installer normally mounts Gate SQL into Postgres's first-boot init directory.
    # Gate migration 042 references Tally tables, which do not exist until the dump is
    # restored. Stage an empty database; the Gate worker applies Tally then Gate
    # migrations in order when the full stack starts after the import.
    empty_initdb="$state_dir/empty-initdb"
    mkdir -p "$empty_initdb"
    if GGATE_DB_MIGRATIONS_DIR="$empty_initdb" sh "$installer" --console-url "$temp_url" --tls-cert "$cert" --tls-key "$key" \
        --registration-key-file "$registration_file" --dir "$gate_dir" --version "$version" \
        --http-port "$stage_http_port" --https-port "$stage_port" --tally-import-pg-port "$import_pg_port" --stage-for-tally-import; then
        :
    else
        postgres_container="$(compose_gate ps -a -q postgres 2>/dev/null || true)"
        if [ -n "$postgres_container" ]; then
            postgres_tail="$(docker logs --tail 80 "$postgres_container" 2>&1 || true)"
            if [[ "$postgres_tail" == *'relation "connector_states" does not exist'* ]]; then
                record failure_code gate_migrations_before_tally
            fi
        fi
        fail "Gate PostgreSQL staging failed; inspect prepare.log and the Gate Postgres container log"
    fi
    rm -f "$registration_file"
    progress "Gate import database is healthy"
    cp "$gate_dir/.env" "$state_dir/gate.env"

    check_migration_versions

    record status copying
    progress "Pausing Tally writers and saving a database backup"
    trap 'if [ -f "$state_dir/writers-paused" ]; then record status failed; resume_tally; fi' EXIT
    record writers-paused yes
    if combined_runtime; then rm -f "$maintenance_dir/writers-drained"; fi
    enable_read_only
    if combined_runtime; then
        pause_combined_writers
    elif [ "$mode" = dev ]; then
        pause_dev_processes
    else
        compose_tally stop collector
    fi
    backup="$state_dir/tally-before-gate.dump"
    tally_dump > "$backup"
    [ -s "$backup" ] || fail "Tally backup is empty"
    record backup_sha256 "$(sha256_file "$backup")"
    echo "Tally backup saved and checksummed at $backup"
    progress "Tally database backup saved and checksummed"
    compose_gate exec -T postgres dropdb -U ggate --if-exists --force ggate
    compose_gate exec -T postgres createdb -U ggate ggate
    compose_gate exec -T postgres pg_restore -U ggate -d ggate --no-owner --no-acl --exit-on-error < "$backup"
    prepare_imported_migration_ledger
    progress "Tally data restored to Gate PostgreSQL"
    progress "Re-encrypting connector credentials for Gate"
    TALLY_UPGRADE_SOURCE_ENV="$state_dir/tally.env" TALLY_UPGRADE_GATE_ENV="$gate_dir/.env" TALLY_IMPORT_PG_PORT="$import_pg_port" \
        "${rekey[@]}"
    sh "$installer" --console-url "$temp_url" --tls-cert "$cert" --tls-key "$key" \
        --dir "$gate_dir" --version "$version" --http-port "$stage_http_port" --https-port "$stage_port"
    set_gate_env GGATE_PUBLISH_HOST 0.0.0.0
    compose_gate up -d --no-deps --force-recreate router
    progress "Gate services started on review HTTPS port $stage_port"
    progress "Importing standalone Tally accounts into Gate IAM"
    import_users
    progress "Tally accounts imported into Gate IAM"
    progress "Reconciling Tally AI Registry decisions in Gate"
    reconcile_registry
    verify_url "$temp_url" "$cert"
    verify_counts
    progress "Gate health and Tally record counts verified"
    record status ready_for_cutover
    trap - EXIT
    echo "Gate is healthy at $temp_url and Tally data was copied. Tally remains read-only. Open Gate and review it before cutover."
elif [ "$phase" = cutover ]; then
    [ "${1:-}" = "--final-url" ] || fail "expected --final-url URL"; final_url="${2:-}"; shift 2
    [ "${1:-}" = "--tls-cert" ] || fail "expected --tls-cert"; cert="${2:-}"; shift 2
    [ "${1:-}" = "--tls-key" ] || fail "expected --tls-key"; key="${2:-}"; shift 2
    [ $# -eq 0 ] || fail "unexpected cutover arguments"
    if [ "$(read_record status)" != ready_for_cutover ]; then
        pre_switch_cutover_failure \
            || fail "this cutover may have started switching services and cannot be retried automatically"
    fi
    record cutover_stage preflight
    record status cutting_over
    # Revalidate the installed key immediately before any service switching. Saved expiry metadata
    # may be stale after a portal admin extends/deactivates the license. Stream the secret over
    # stdin; only the verified expiry is recorded or logged.
    verified_expiry="$(compose_gate exec -T postgres psql -U ggate -d ggate -Atqc \
        "SELECT value #>> '{}' FROM settings WHERE key='product_registration_key'" | \
        python3 "$root/scripts/validate-gate-registration.py")" \
        || fail "Gate registration is not active. Contact support@godel-labs.ai before cutover."
    record expires_at "$verified_expiry"
    rm -f "$state_dir/failure_reason" "$state_dir/cutover-exit"
    [[ "$final_url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail "final URL must be an HTTPS hostname with an optional port"
    final_authority="${final_url#https://}"
    final_host="${final_authority%%:*}"
    final_port=443
    [ "$final_authority" = "$final_host" ] || final_port="${final_authority##*:}"
    [ "$final_port" -ge 1 ] && [ "$final_port" -le 65535 ] || fail "final HTTPS port is invalid"
    validate_final_tls "$cert" "$key" "$final_host"
    review_port="$(read_record temp_url)"
    review_port="${review_port##*:}"
    tally_router_handoff=0
    if [ "$final_port" != "$review_port" ] && ! port_available "$final_port" 2>/dev/null; then
        tally_router_publishes_port "$final_port" \
            || fail "final HTTPS port $final_port is occupied by another service; Tally remains running"
        tally_router_handoff=1
    fi
    verify_url "$(read_record temp_url)" "$(read_record staging_cert)"
    progress "Re-checking copied Tally records before cutover"
    verify_counts
    progress "Copied Tally records remain present in Gate"
    gate_certs="$(read_record gate_dir)/certs"
    backup="$state_dir/cutover-review-backup"
    mkdir -p "$backup"
    chmod 700 "$backup"
    cp "$(read_record gate_dir)/.env" "$backup/gate.env"
    cp "$gate_certs/console.crt" "$backup/console.crt"
    cp "$gate_certs/console.key" "$backup/console.key"
    rm -f "$backup/.self-signed"
    [ ! -f "$gate_certs/.self-signed" ] || cp "$gate_certs/.self-signed" "$backup/.self-signed"
    chmod 600 "$backup"/* "$backup/gate.env"
    [ ! -f "$backup/.self-signed" ] || chmod 600 "$backup/.self-signed"
    tally_router_paused=0
    gate_activated=0
    trap 'restore_cutover_review "$?"' EXIT
    cp "$cert" "$gate_certs/.console.crt.new"
    cp "$key" "$gate_certs/.console.key.new"
    chmod 644 "$gate_certs/.console.crt.new"
    chmod 600 "$gate_certs/.console.key.new"
    mv "$gate_certs/.console.key.new" "$gate_certs/console.key"
    mv "$gate_certs/.console.crt.new" "$gate_certs/console.crt"
    rm -f "$gate_certs/.self-signed"
    set_gate_env CONSOLE_URL "$final_url"
    set_gate_env FILE_SERVER_PUBLIC_ENDPOINT "$final_url"
    # Verify the production certificate and final API configuration on Gate's
    # existing review port while Tally is still serving its original address.
    set_gate_env GGATE_TALLY_MIGRATION_MODE 1
    progress "Checking Gate with the production certificate before the switch"
    compose_gate up -d --no-deps --force-recreate --wait --wait-timeout 120 worker
    compose_gate up -d --no-deps --force-recreate --wait --wait-timeout 120 api
    start_gate_router || fail "Gate router could not start with the production certificate; Tally was retained"
    verify_url "https://$final_host:$review_port" "$cert" public \
        || fail "Gate HTTPS verification failed before the switch; Tally was retained"
    progress "Gate production certificate and API verified on the review port"
    record cutover_stage switching
    record status cutting_over
    if [ "$tally_router_handoff" = 1 ]; then
        tally_router_paused=1
        pause_tally_http
        progress "Waiting for Tally HTTPS port $final_port to be released; Tally applications remain running"
        wait_for_port_release "$final_port"
    fi
    set_gate_env HTTPS_PORT "$final_port"
    final_http_port=80
    if [ "$final_port" = 80 ] || ! port_available 80; then
        final_http_port="$(read_record stage_http_port)"
        progress "Using Gate's review HTTP port $final_http_port to avoid a port conflict"
    fi
    set_gate_env HTTP_PORT "$final_http_port"
    set_gate_env GGATE_PUBLISH_HOST 0.0.0.0
    start_gate_router || fail "Gate router could not bind the final ports; Tally application services were retained"
    verify_url "$final_url" "$cert" public \
        || fail "Gate final HTTPS verification failed; Tally application services were retained"
    gate_activated=1
    record cutover_stage activating
    set_gate_env GGATE_TALLY_MIGRATION_MODE 0
    progress "Activating Gate at the final URL"
    compose_gate up -d --no-deps --force-recreate --wait --wait-timeout 120 worker
    progress "Gate worker and API switched to the final URL"
    verify_url "$final_url" "$cert" public
    progress "Gate final HTTPS endpoint verified"
    record final_url "$final_url"
    # Retire Tally only after Gate's final router, TLS, API and worker are ready.
    # From here onward preserve the healthy Gate endpoint if Tally cleanup fails.
    trap 'if [ "$?" != 0 ]; then record status cutover_failed; fi' EXIT
    record cutover_stage retiring_tally
    if ! combined_runtime && [ "$(read_record mode)" = dev ]; then
        if [ -f "$state_dir/paused-pids" ]; then
            while IFS= read -r pid; do kill -KILL "$pid" 2>/dev/null || true; done < "$state_dir/paused-pids"
            rm -f "$state_dir/paused-pids"
        fi
        if [ -f "$TALLY_UPGRADE_STATE_DIR/dev-processes" ]; then
            while IFS='=' read -r label pid; do
                case "$label" in API_PID|COLLECTOR_PID|WEB_PID) kill_tree "$pid" ;; esac
            done < "$TALLY_UPGRADE_STATE_DIR/dev-processes"
        fi
    fi
    if combined_runtime; then
        # Leave customer/native/database containers intact; the application retires itself last.
        progress "Gate is verified; retiring the standalone Tally application and retaining its databases"
    else
        compose_tally down \
            || fail "Gate HTTPS is healthy, but Tally shutdown needs attention; Gate remains running"
        docker volume inspect "$(read_record tally_volume)" >/dev/null || fail "Tally data volume is missing after shutdown"
        progress "Tally containers stopped; volume retained"
        disable_read_only
    fi
    rm -f "$state_dir/writers-paused"
    rm -rf -- "$backup"
    record cutover_stage complete
    record status gate_live
    echo "Gate is live at $final_url. Tally source data and its backup remain intact."
    if combined_runtime; then
        # Keep read-only sticky so a supervisor or manual restart cannot resume stale writers.
        : > "$maintenance_dir/retired"
        if [ "$(read_record mode)" = combined-compose ]; then compose_tally stop tallyd; fi
    fi
elif [ "$phase" = status ]; then
    if [ -f "$state_dir/status" ]; then
        echo "Status: $(read_record status)"
        [ ! -f "$state_dir/version" ] || echo "Gate version: $(read_record version)"
        [ ! -f "$state_dir/temp_url" ] || echo "Gate review URL: $(read_record temp_url)"
        [ ! -f "$state_dir/final_url" ] || echo "Final URL: $(read_record final_url)"
    else echo "No Gate upgrade has been started"; fi
elif [ "$phase" = import-users ]; then
    [ "$(read_record status)" = gate_live ] \
        || fail "post-cutover account repair requires Gate to be live"
    progress "Reconciling standalone Tally accounts in live Gate IAM"
    import_users
    verify_users
    rm -f "$state_dir/failure_reason"
    progress "Verified Tally accounts in live Gate IAM"
elif [ "$phase" = cleanup ]; then
    [ "$(read_record status)" = gate_live ] \
        || fail "only a completed Gate upgrade can be cleaned"
    final_url="$(read_record final_url)"
    verify_url "$final_url" "$(read_record requested_tls_cert)" public \
        || fail "Gate is not healthy at $final_url; upgrade recovery files were retained"
    completion_dir="$(dirname "$state_dir")/gate-upgrade-completions"
    mkdir -p "$completion_dir"
    chmod 700 "$completion_dir"
    completion="$completion_dir/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    {
        printf 'status=gate_live\n'
        printf 'version=%s\n' "$(read_record version)"
        printf 'cleaned_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$completion"
    chmod 600 "$completion"
    rm -rf -- "$state_dir"
    echo "Gate is healthy. Upgrade working files were removed; Gate and Tally volumes were retained."
elif [ "$phase" = cancel ]; then
    if [ "$(read_record status)" != ready_for_cutover ]; then
        pre_switch_cutover_failure \
            || fail "only a prepared or pre-switch failed cutover can be cancelled"
    fi
    compose_gate down  # Retain the staged Gate data volume for inspection.
    resume_tally
    rm -f "$state_dir/failure_reason" "$state_dir/cutover_stage"
    record status cancelled
    echo "Tally writers resumed. Gate is stopped; both data volumes and the backup remain."
elif [ "$phase" = reset ]; then
    case "$(read_record status)" in failed|cancelled) : ;; *) fail "only failed or cancelled upgrades can be reset" ;; esac
    [ ! -f "$state_dir/writers-paused" ] || fail "Tally writers are still paused; resume them before reset"
    archive_dir="$(dirname "$state_dir")/gate-upgrade-attempts/$(date -u +%Y%m%dT%H%M%SZ)-$$"
    mkdir -p "$archive_dir"
    chmod 700 "$archive_dir"
    if [ -f "$state_dir/gate_dir" ]; then
        failed_gate_dir="$(read_record gate_dir)"
        if [ -d "$failed_gate_dir" ] && [ -n "$(ls -A "$failed_gate_dir")" ]; then
            # Keep all partial Gate files and its named volumes. A new install at the
            # original path gets a fresh Compose project and empty database volume.
            if [ -f "$failed_gate_dir/docker-compose.yml" ] && [ -f "$failed_gate_dir/.env" ]; then
                compose_gate down
            fi
            mv "$failed_gate_dir" "$archive_dir/gate-install"
        fi
    fi
    mv "$state_dir"/* "$archive_dir"/
    echo "Previous upgrade receipt and partial Gate files preserved at $archive_dir. Gate and Tally volumes were retained."
else
    fail "usage: $0 prepare|cutover|import-users|cleanup|status|cancel|reset"
fi
