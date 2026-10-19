#!/usr/bin/env bash
# Drive the authenticated vendor push receiver the way Zscaler NSS, Palo Alto
# Strata, and Cloudflare Logpush would: real HTTP POSTs of real vendor-format
# batches, including the auth-failure and vendor-probe paths.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lab-env.sh"
cd "$TALLY_REPO"
BIN=./target/debug/tally-collector

run_case() {
  local adapter="$1" file="$2" port="$3" encoding="$4"
  echo "════════ $adapter ($encoding) ════════"
  $BIN receive --adapter "$adapter" --bind "127.0.0.1:$port" \
    --authorization-env TALLY_RECEIVER_AUTHORIZATION \
    --source-lineage-id "lab_${adapter//-/_}" > "$LAB/out/receiver-$adapter.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 25); do
    curl -sf -m 2 "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && break
    sleep 1
  done

  printf '  healthz            -> %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz")"

  printf '  no auth            -> %s (expect 401)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' --data-binary @"$file" \
        "http://127.0.0.1:$port/ingest")"

  printf '  wrong auth         -> %s (expect 401)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H 'Authorization: Bearer wrong-secret' \
        -H 'Content-Type: application/json' --data-binary @"$file" \
        "http://127.0.0.1:$port/ingest")"

  if [ "$encoding" = "gzip" ]; then
    gzip -c "$file" > "$file.gz"
    printf '  real batch (gzip)  -> %s (expect 204)\n' \
      "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
          -H "Authorization: $TALLY_RECEIVER_AUTHORIZATION" \
          -H 'Content-Type: application/json' -H 'Content-Encoding: gzip' \
          --data-binary @"$file.gz" "http://127.0.0.1:$port/ingest")"
  else
    printf '  real batch         -> %s (expect 204)\n' \
      "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
          -H "Authorization: $TALLY_RECEIVER_AUTHORIZATION" \
          -H 'Content-Type: application/json' --data-binary @"$file" \
          "http://127.0.0.1:$port/ingest")"
  fi

  printf '  replay same batch  -> %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: $TALLY_RECEIVER_AUTHORIZATION" \
        -H 'Content-Type: application/json' --data-binary @"$file" \
        "http://127.0.0.1:$port/ingest")"

  printf '  malformed record   -> %s (expect 400)\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST \
        -H "Authorization: $TALLY_RECEIVER_AUTHORIZATION" \
        -H 'Content-Type: application/json' --data-binary '{"not":"a vendor record"}' \
        "http://127.0.0.1:$port/ingest")"

  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  echo
}

run_case cloudflare-gateway "$LAB/out/cloudflare-gateway.ndjson" 18790 gzip
run_case zscaler            "$LAB/out/zscaler.ndjson"            18791 plain
run_case palo-alto          "$LAB/out/palo-alto.ndjson"          18792 gzip
