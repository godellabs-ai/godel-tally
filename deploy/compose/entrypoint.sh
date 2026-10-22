#!/usr/bin/env bash
# Container entrypoint: select or create the HTTPS certificate, then run tallyd without root.
# A certificate supplied as /tls/tally.crt and /tls/tally.key is used when present; otherwise a
# self-signed certificate is created once in the data volume and reused across restarts.
set -euo pipefail
tls=/data/tls
supplied=0
[ ! -e /tls/tally.crt ] && [ ! -e /tls/tally.key ] || supplied=1
if [ "$supplied" = 1 ] && [ -r /tls/tally.crt ] && [ -r /tls/tally.key ]; then
    # Copy each start so a renewed certificate is picked up by restarting the container.
    mkdir -p "$tls/supplied"
    (umask 077; cat /tls/tally.crt > "$tls/supplied/tally.crt"; cat /tls/tally.key > "$tls/supplied/tally.key")
elif [ "$supplied" = 0 ]; then
    rm -rf "$tls/supplied"
fi
if [ "$(id -u)" = 0 ]; then
    # Root only stages files that may be readable by root alone, such as Let's Encrypt keys.
    mkdir -p "$tls"
    chown 65532:65532 /data
    chown -R 65532:65532 "$tls"
    exec setpriv --reuid=65532 --regid=65532 --clear-groups -- "$0" "$@"
fi
unset TALLY_TLS_CERT_FILE TALLY_TLS_KEY_FILE
if [ -f "$tls/supplied/tally.crt" ]; then
    export TALLY_TLS_CERT_FILE="$tls/supplied/tally.crt" TALLY_TLS_KEY_FILE="$tls/supplied/tally.key"
elif [ "$supplied" = 1 ]; then
    echo "Tally cannot read /tls/tally.crt and /tls/tally.key. Make both files readable, then restart." >&2
    exit 1
fi
TALLY_TLS_DIR="$tls" bash /usr/local/lib/tally/scripts/ensure-tally-tls.sh
export TALLY_TLS_CERT_FILE="${TALLY_TLS_CERT_FILE:-$tls/tally.crt}" TALLY_TLS_KEY_FILE="${TALLY_TLS_KEY_FILE:-$tls/tally.key}"
exec tallyd "$@"
