#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if ! declare -p "$name" >/dev/null 2>&1; then
    printf 'Required environment variable is not set: %s\n' "$name" >&2
    exit 1
  fi
  if [[ -z "${!name}" ]]; then
    printf 'Required environment variable is not set: %s\n' "$name" >&2
    exit 1
  fi
}

require_env TALLY_GCP_PROJECT_ID
require_env TALLY_GCP_LOCATION
require_env TALLY_GCP_MODEL

exec > >(tee /var/log/tally-vertex-test.log | logger -t tally-vertex-test) 2>&1

project_id="$TALLY_GCP_PROJECT_ID"
location="$TALLY_GCP_LOCATION"
model="$TALLY_GCP_MODEL"
metadata_url="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
access_token=""

for attempt in $(seq 1 20); do
  token_response="$(curl -fsS -H 'Metadata-Flavor: Google' "$metadata_url" || true)"
  access_token="$(sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p' <<<"$token_response")"
  if [[ -n "$access_token" ]]; then
    break
  fi
  printf 'Waiting for instance service-account token (attempt %s)\n' "$attempt"
  sleep 3
done

if [[ -z "$access_token" ]]; then
  printf 'Could not obtain an instance service-account token\n' >&2
  exit 1
fi

endpoint="https://${location}-aiplatform.googleapis.com/v1/projects/${project_id}/locations/${location}/publishers/google/models/${model}:generateContent"
response_code="$(curl -sS -o /var/tmp/tally-vertex-response.json -w '%{http_code}' \
  -H "Authorization: Bearer $access_token" \
  -H 'Content-Type: application/json' \
  --data-binary '{"contents":[{"role":"user","parts":[{"text":"Reply with exactly: tally-gcp-flow-ok"}]}],"generationConfig":{"maxOutputTokens":24,"temperature":0}}' \
  "$endpoint")"

printf 'Vertex response status: %s\n' "$response_code"
if [[ "$response_code" != "200" ]]; then
  sed -n '1,20p' /var/tmp/tally-vertex-response.json
  exit 1
fi
printf 'Tally Vertex request completed successfully\n'
