#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tally_host="${TALLY_URL:-https://localhost}"
tally_host="${tally_host#https://}"
tally_host="${tally_host%%:*}"
case "$tally_host" in ''|*[!A-Za-z0-9.-]*) echo "Invalid TALLY_URL hostname" >&2; exit 1 ;; esac

key_matches() {
    local cert_pub key_pub
    cert_pub="$(openssl x509 -in "$1" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    key_pub="$(openssl pkey -in "$2" -passin pass: -pubout -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
    [ "$cert_pub" = "$key_pub" ]
}

if [ -n "${TALLY_TLS_CERT_FILE:-}" ] || [ -n "${TALLY_TLS_KEY_FILE:-}" ]; then
    [ -f "${TALLY_TLS_CERT_FILE:-}" ] && [ -r "${TALLY_TLS_CERT_FILE:-}" ] \
        && [ -f "${TALLY_TLS_KEY_FILE:-}" ] && [ -r "${TALLY_TLS_KEY_FILE:-}" ] \
        || { echo "TALLY_TLS_CERT_FILE and TALLY_TLS_KEY_FILE must both be readable" >&2; exit 1; }
    key_matches "$TALLY_TLS_CERT_FILE" "$TALLY_TLS_KEY_FILE" || { echo "Tally certificate and key do not match" >&2; exit 1; }
    bash "$repo_dir/scripts/check-tls-host.sh" "$TALLY_TLS_CERT_FILE" "$tally_host" || { echo "Tally certificate does not cover $tally_host" >&2; exit 1; }
    openssl x509 -in "$TALLY_TLS_CERT_FILE" -noout -checkend 0 >/dev/null 2>&1 || { echo "Tally certificate has expired" >&2; exit 1; }
    echo "Using the supplied Tally TLS certificate: $TALLY_TLS_CERT_FILE"
    exit 0
fi

tls_dir="${TALLY_TLS_DIR:-$repo_dir/.local/tls}"
mkdir -p "$tls_dir"

certificate_valid() {
    [ -s "$tls_dir/tally.crt" ] && [ -s "$tls_dir/tally.key" ] || return 1
    # Browser exceptions are tied to the certificate fingerprint. Reuse any
    # valid pair, regardless of how it was issued, until it actually expires.
    openssl x509 -in "$tls_dir/tally.crt" -noout -checkend 0 >/dev/null 2>&1 || return 1
    key_matches "$tls_dir/tally.crt" "$tls_dir/tally.key" || return 1
    bash "$repo_dir/scripts/check-tls-host.sh" "$tls_dir/tally.crt" "$tally_host" >/dev/null 2>&1 || return 1
}

if ! certificate_valid; then
    command -v openssl >/dev/null || { echo "openssl is required for a development certificate" >&2; exit 1; }
    # Validate both files before replacing them. Write into the existing files:
    # Preserve existing certificate paths when renewing local TLS.
    staging="$(mktemp -d "$tls_dir/.generate.XXXXXX")"
    trap 'rm -rf "$staging"' EXIT
    alt_name="DNS:localhost,IP:127.0.0.1,IP:::1"
    case "$tally_host" in
        localhost|127.0.0.1) ;;
        *[!0-9.]*) alt_name="$alt_name,DNS:$tally_host" ;;
        *) alt_name="$alt_name,IP:$tally_host" ;;
    esac
    (umask 077; openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -subj "/CN=$tally_host" -addext "subjectAltName=$alt_name" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" \
        -keyout "$staging/tally.key" -out "$staging/tally.crt" >/dev/null 2>&1)
    key_matches "$staging/tally.crt" "$staging/tally.key"
    (umask 077; cat "$staging/tally.key" > "$tls_dir/tally.key"; cat "$staging/tally.crt" > "$tls_dir/tally.crt")
    chmod 600 "$tls_dir/tally.key"
    chmod 644 "$tls_dir/tally.crt"
    echo "Created a self-signed Tally server certificate in .local/tls."
fi

echo "Tally is using local TLS. Accept the browser warning for self-signed certificates."
