#!/usr/bin/env bash
# Verify the certificate SAN against a hostname on OpenSSL and macOS LibreSSL.
set -euo pipefail
[ "$#" -eq 2 ] || { echo "usage: check-tls-host.sh CERT HOST" >&2; exit 2; }
cert="$1"
host="$2"

help_text="$(openssl x509 -help 2>&1 || true)"
if grep -q -- '-checkhost' <<< "$help_text"; then
    case "$host" in
        *:*) openssl x509 -in "$cert" -noout -checkip "$host" >/dev/null 2>&1 ;;
        *[!0-9.]*) openssl x509 -in "$cert" -noout -checkhost "$host" >/dev/null 2>&1 ;;
        *) openssl x509 -in "$cert" -noout -checkip "$host" >/dev/null 2>&1 ;;
    esac
    exit $?
fi

# Installed Tally includes a certificate hostname verifier; no Python/Homebrew is needed.
if [ -n "${TALLY_BINARY:-}" ] && [ -x "$TALLY_BINARY" ]; then
    exec "$TALLY_BINARY" check-tls-host "$cert" "$host"
fi

# Apple's LibreSSL omits -checkhost/-checkip. Python's certificate decoder exposes
# the parsed SANs, avoiding fragile parsing of `openssl x509 -text` output.
command -v python3 >/dev/null || { echo "Python 3 is required to inspect TLS hostnames with LibreSSL" >&2; exit 2; }
python3 - "$cert" "$host" <<'PY'
import ipaddress
import ssl
import sys

certificate = ssl._ssl._test_decode_cert(sys.argv[1])
hostname = sys.argv[2].rstrip('.').lower()
try:
    address = ipaddress.ip_address(hostname)
except ValueError:
    address = None

for kind, value in certificate.get('subjectAltName', ()):
    if address is not None:
        if kind == 'IP Address':
            try:
                if ipaddress.ip_address(value) == address:
                    sys.exit(0)
            except ValueError:
                pass
    elif kind == 'DNS':
        pattern = value.rstrip('.').lower()
        if pattern == hostname:
            sys.exit(0)
        if pattern.startswith('*.') and pattern.count('*') == 1:
            suffix = pattern[1:]
            if hostname.endswith(suffix) and hostname[:-len(suffix)] and '.' not in hostname[:-len(suffix)]:
                sys.exit(0)
sys.exit(1)
PY
