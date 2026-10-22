#!/usr/bin/env bash
# Standalone downloader and shared installer presentation. Bash 3.2 compatible.
# Release bundles include this file so both installation phases use the same UI.
set -euo pipefail

installer_line() {
    local color="$1" label="$2"; shift 2
    if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
        printf '\033[%sm%s\033[0m %s\n' "$color" "$label" "$*"
    else
        printf '%s %s\n' "$label" "$*"
    fi
}
progress() { installer_line '36' '  >' "$*"; }
success() { installer_line '32;1' '  OK' "$*"; }
notice() { installer_line '33' '  NOTE' "$*"; }
fail() { install_reason="$*"; exit 1; }
installer_step() {
    install_step="Step $1 of 7: $2"
    install_hint="$3"
    printf '\n'
    installer_line '36;1' "[$1/7]" "$2"
}
installer_init() {
    install_step='Checking installation options'
    install_reason=
    install_hint='Check the message above, then run the same installation command again.'
    install_stage_dir=
    install_lock_dir=
    install_child_failed=0
    trap 'installer_exit "$?"' EXIT
    trap 'install_reason="Installation was cancelled."; exit 130' INT
    trap 'install_reason="Installation was interrupted."; exit 143' TERM
}
installer_exit() {
    local status="$1"
    trap - EXIT
    if [ "$status" != 0 ] && [ "$install_child_failed" = 0 ]; then
        {
            printf '\n'
            installer_line '31;1' 'STOPPED' 'Tally setup did not finish.'
            printf '  Where: %s\n' "$install_step"
            printf '  What happened: %s\n' "${install_reason:-A required command could not finish (exit code $status).}"
            printf '\n  What to do next:\n  %s\n' "$install_hint"
            if [ -n "${TALLY_ENV_FILE:-}" ] && [ -f "$TALLY_ENV_FILE" ]; then
                printf '\n  Saved settings: %s\n' "$TALLY_ENV_FILE"
                printf '  Keep this file. Rerunning the installer reuses your saved settings.\n'
            fi
        } >&2
    fi
    [ -z "$install_stage_dir" ] || rm -rf "$install_stage_dir"
    [ -z "$install_lock_dir" ] || rmdir "$install_lock_dir" 2>/dev/null || true
    exit "$status"
}
installer_prerequisites() {
    local tool help_text
    install_hint='Install the missing tool named in the message, then rerun this installer.'
    for tool in curl tar openssl; do
        command -v "$tool" >/dev/null || fail "The required tool '$tool' is missing."
    done
    [ "${1:-tls}" != tools ] || return 0
    help_text="$(openssl req -help 2>&1 || true)"
    if [ -z "${TALLY_TLS_CERT_FILE:-}" ] && [ -z "${TALLY_TLS_KEY_FILE:-}" ] && [[ "$help_text" != *-addext* ]]; then
        install_hint='Use a supported operating system with OpenSSL 1.1.1+ or macOS LibreSSL, or supply your own TALLY_TLS_CERT_FILE and TALLY_TLS_KEY_FILE.'
        fail 'The installed OpenSSL cannot create the secure browser certificate Tally needs.'
    fi

}
installer_service_hint() {
    local name="$1"
    if [ "$(uname -s)" = Darwin ]; then
        printf -v install_hint 'Check the startup details with this command, or ask your administrator to help:\n    tail -n 50 %q\n  Correct the reported problem, then rerun the installer.' "$TALLY_DATA_DIR/$name.log"
    else
        printf -v install_hint 'Check the startup details with this command, or ask your administrator to help:\n    journalctl --user -u tally-%s -n 50 --no-pager\n  Correct the reported problem, then rerun the installer.' "$name"
    fi
}
installer_help() {
    cat <<'HELP'
Gödel Tally setup

Download Tally, prepare its databases, and open it in your browser.
Run as your normal user. Private database downloads do not use sudo or package managers.

  bash install.sh                     Install and start Tally
  bash install.sh --port 9443          Use a different browser port
  bash install.sh --dry-run            Preview the plan without making changes

Options:
  --db MODE             Private downloads: native (default); or docker, apple, existing
  --postgres MODE       Choose a different mode for PostgreSQL (settings storage)
  --clickhouse MODE     Choose a different mode for ClickHouse (activity storage)
  --port PORT           HTTPS port, 1024–65535 (default 2357; saved on reinstall)
  --no-start            Set up automatic startup but do not start Tally now
  --no-service          Install Tally for manual startup
                        Private databases stay stopped. Container databases may still start.
  --dry-run             Preview only; no downloads or installation
  --help                Show this help

Advanced environment settings:
  TALLY_VERSION (release tag, default latest), TALLY_GITHUB_REPO,
  TALLY_HOME (default ~/.godel-tally), TALLY_RUNTIME_DIR,
  TALLY_INSTALL_DIR, TALLY_DATA_DIR, TALLY_CONFIG_DIR, TALLY_URL,
  TALLY_POSTGRES_URL / TALLY_CLICKHOUSE_URL (required for existing mode).
  NO_COLOR=1 disables colors; saved/piped output is plain text automatically.
HELP
}
installer_main() {
    installer_init
    local repo="${TALLY_GITHUB_REPO:-godellabs-ai/godel-tally}" version="${TALLY_VERSION:-latest}"
    local os arch platform asset release_url base expected actual status
    case "$(uname -s)" in Linux) os=linux; platform=Linux ;; Darwin) os=darwin; platform=macOS ;; *) fail 'Tally supports Linux and macOS.' ;; esac
    case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) fail 'Tally supports Intel/AMD 64-bit and Apple silicon/ARM 64-bit computers.' ;; esac
    case "$version" in *[!A-Za-z0-9._-]*|'') fail 'Invalid TALLY_VERSION' ;; esac
    case "$repo" in *[!A-Za-z0-9._/-]*|'') fail 'Invalid TALLY_GITHUB_REPO' ;; esac
    local args=("$@") dry_run=0 selected_port='2357 (or saved port)' mode='native (or saved choice)' pg_mode= ch_mode= startup='Start automatically when you log in'
    install_hint='Run bash install.sh --help to see available options.'
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help) installer_help; return ;;
            --port)
                [ "$#" -ge 2 ] && [[ "$2" =~ ^[1-9][0-9]{3,4}$ ]] && [ "$2" -ge 1024 ] && [ "$2" -le 65535 ] || fail '--port must be between 1024 and 65535'
                selected_port="$2"; shift 2 ;;
            --db|--postgres|--clickhouse)
                [ "$#" -ge 2 ] || fail "Missing value for $1"
                case "$2" in native|docker|apple|existing) ;; *) fail "Invalid database mode: $2" ;; esac
                case "$1" in --db) mode="$2" ;; --postgres) pg_mode="$2" ;; --clickhouse) ch_mode="$2" ;; esac
                shift 2 ;;
            --dry-run) dry_run=1; shift ;;
            --no-start) [ "$startup" = 'Manual startup' ] || startup='Set up automatic startup; do not start Tally now'; shift ;;
            --no-service) startup='Manual startup'; shift ;;
            *) fail "Unknown option: $1" ;;
        esac
    done
    printf '\n'
    installer_line '35;1' 'Gödel Tally' '— guided setup'
    printf '  Your computer: %s (%s)\n  Release: %s\n' "$platform" "$arch" "$version"
    printf '  PostgreSQL (settings): %s\n  ClickHouse (activity): %s\n' "${pg_mode:-$mode}" "${ch_mode:-$mode}"
    printf '  HTTPS port: %s\n  Startup: %s\n' "$selected_port" "$startup"
    printf '\n  We will check your computer, download Tally, prepare storage,\n  and get the browser console ready.\n'
    if [ "$dry_run" = 1 ]; then
        notice 'Preview only. Nothing was downloaded, installed, or started.'
        return
    fi
    installer_step 1 'Check your computer' 'Run the installer as your normal user, without sudo.'
    [ "$(id -u)" != 0 ] || fail 'Run the installer as your normal user; without sudo.'
    installer_prerequisites tools
    command -v sha256sum >/dev/null || command -v shasum >/dev/null || fail 'A SHA-256 checksum tool (shasum or sha256sum) is required to verify the download.'
    success 'Required tools are available.'
    installer_step 2 'Download Tally' 'Check your internet connection and access to github.com, then run the same command again.'
    asset="tallyd-${os}-${arch}.tar.gz"
    if [ "$version" = latest ]; then
        progress 'Finding the latest release on GitHub...'
        # Resolve once so an update cannot mix archives and checksums from different releases.
        release_url="$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --retry 3 \
            -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")"
        case "$release_url" in
            "https://github.com/$repo/releases/tag/"*) version="${release_url##*/}" ;;
            *) fail 'Could not resolve the latest Tally release' ;;
        esac
        case "$version" in *[!A-Za-z0-9._-]*|'') fail 'Invalid release tag' ;; esac
    fi
    base="https://github.com/$repo/releases/download/$version"
    install_stage_dir="$(mktemp -d)"
    progress "Downloading $version for $platform ($arch)..."
    curl --proto '=https' --tlsv1.2 -fL --progress-bar --retry 3 "$base/$asset" -o "$install_stage_dir/$asset"
    success 'Download complete.'
    installer_step 3 'Verify the download' 'Download again by rerunning this command. If verification still fails, share this error with your administrator.'
    progress 'Checking that the file matches the published release...'
    curl --proto '=https' --tlsv1.2 -fLsS --retry 3 "$base/SHA256SUMS" -o "$install_stage_dir/SHA256SUMS"
    expected="$(awk -v name="$asset" '$2 == name {print $1}' "$install_stage_dir/SHA256SUMS")"
    [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || fail 'Release checksum missing or ambiguous'
    if command -v sha256sum >/dev/null; then actual="$(sha256sum "$install_stage_dir/$asset" | cut -d ' ' -f1)"
    else actual="$(shasum -a 256 "$install_stage_dir/$asset" | cut -d ' ' -f1)"; fi
    [ "$actual" = "$expected" ] || fail 'Release checksum mismatch. The downloaded file could not be verified.'
    # These archives are flat and contain only the binary, documentation and installer helpers.
    if tar -tzf "$install_stage_dir/$asset" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then fail 'Unsafe archive paths'; fi
    tar -xzf "$install_stage_dir/$asset" -C "$install_stage_dir"
    success 'Download verified and unpacked.'
    install_step='Preparing the application and databases'
    install_hint='See the setup error above, then rerun the installer after correcting it.'
    status=0
    if [ "${#args[@]}" -gt 0 ]; then bash "$install_stage_dir/scripts/install-runtime.sh" "$install_stage_dir" "${args[@]}" || status=$?
    else bash "$install_stage_dir/scripts/install-runtime.sh" "$install_stage_dir" || status=$?; fi
    # New bundles report their own failure. Older releases still get a bootstrap summary.
    if [ -f "$install_stage_dir/install.sh" ]; then install_child_failed=1; fi
    exit "$status"
}

if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then installer_main "$@"; fi
