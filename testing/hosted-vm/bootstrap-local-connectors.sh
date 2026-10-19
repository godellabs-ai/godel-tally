#!/usr/bin/env bash
set -euo pipefail

# Run this on the Ubuntu host that runs the standalone Tally Docker Compose stack.
# It creates only local/no-license fixtures: Ollama, LiteLLM, a nested k3s cluster,
# one real local inference request, and an authorized one-host Native Scanner job.

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

for name in \
  TALLY_BASE_URL \
  TALLY_NETWORK \
  TALLY_COLLECTOR_CONTAINER \
  TALLY_TEST_USER \
  TALLY_TEST_STATE_DIR; do
  require_env "$name"
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="$TALLY_TEST_STATE_DIR"
DOCKER=(sudo docker)

require() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Required command is missing: %s\n' "$1" >&2
    exit 1
  }
}

wait_for() {
  local description="$1"
  shift
  for _ in $(seq 1 80); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  printf 'Timed out waiting for %s\n' "$description" >&2
  return 1
}

require curl
require jq
require openssl
require sudo
require docker

curl -fsS "$TALLY_BASE_URL/api/v1/tally/health/ready" >/dev/null
"${DOCKER[@]}" inspect "$TALLY_COLLECTOR_CONTAINER" >/dev/null
"${DOCKER[@]}" network inspect "$TALLY_NETWORK" >/dev/null
install -d -m 700 "$STATE_DIR"

if ! "${DOCKER[@]}" inspect tally-ollama >/dev/null 2>&1; then
  "${DOCKER[@]}" volume create tally-ollama-models >/dev/null
  "${DOCKER[@]}" run -d \
    --name tally-ollama \
    --restart unless-stopped \
    --network "$TALLY_NETWORK" \
    --network-alias ollama.internal \
    -p 127.0.0.1:11434:11434 \
    -v tally-ollama-models:/root/.ollama \
    ollama/ollama:latest >/dev/null
fi
if ! "${DOCKER[@]}" inspect tally-ollama --format '{{json .NetworkSettings.Networks}}' \
  | jq -e --arg network "$TALLY_NETWORK" '.[$network].Aliases | index("ollama.internal")' >/dev/null; then
  "${DOCKER[@]}" network disconnect "$TALLY_NETWORK" tally-ollama >/dev/null 2>&1 || true
  "${DOCKER[@]}" network connect --alias ollama.internal "$TALLY_NETWORK" tally-ollama
fi
wait_for Ollama curl -fsS http://127.0.0.1:11434/api/version
"${DOCKER[@]}" exec tally-ollama ollama pull smollm2:135m >/dev/null

if [[ ! -s "$STATE_DIR/litellm.env" ]]; then
  db_password="$(openssl rand -hex 24)"
  master_key="sk-tally-$(openssl rand -hex 24)"
  umask 077
  printf 'POSTGRES_USER=litellm\nPOSTGRES_DB=litellm\nPOSTGRES_PASSWORD=%s\nDATABASE_URL=postgresql://litellm:%s@tally-litellm-db:5432/litellm\nLITELLM_MASTER_KEY=%s\n' \
    "$db_password" "$db_password" "$master_key" > "$STATE_DIR/litellm.env"
fi
chmod 600 "$STATE_DIR/litellm.env"
install -m 644 "$SCRIPT_DIR/litellm-config.yaml" "$STATE_DIR/litellm-config.yaml"

if ! "${DOCKER[@]}" inspect tally-litellm-db >/dev/null 2>&1; then
  "${DOCKER[@]}" volume create tally-litellm-db-data >/dev/null
  "${DOCKER[@]}" run -d \
    --name tally-litellm-db \
    --restart unless-stopped \
    --network "$TALLY_NETWORK" \
    --env-file "$STATE_DIR/litellm.env" \
    -v tally-litellm-db-data:/var/lib/postgresql \
    --health-cmd='pg_isready -U litellm -d litellm' \
    --health-interval=5s \
    --health-timeout=3s \
    --health-retries=20 \
    postgres:18-alpine >/dev/null
fi
wait_for 'LiteLLM PostgreSQL' "${DOCKER[@]}" exec tally-litellm-db pg_isready -U litellm -d litellm

if "${DOCKER[@]}" inspect tally-litellm >/dev/null 2>&1; then
  "${DOCKER[@]}" rm -f tally-litellm >/dev/null
fi
"${DOCKER[@]}" run -d \
  --name tally-litellm \
  --restart unless-stopped \
  --network "container:$TALLY_COLLECTOR_CONTAINER" \
  --env-file "$STATE_DIR/litellm.env" \
  -v "$STATE_DIR/litellm-config.yaml:/app/config.yaml:ro" \
  ghcr.io/berriai/litellm-non_root:main-stable \
  --config /app/config.yaml --port 4000 >/dev/null

collector_ip="$("${DOCKER[@]}" inspect "$TALLY_COLLECTOR_CONTAINER" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
wait_for LiteLLM curl -fsS "http://$collector_ip:4000/health/readiness"

set -a
# shellcheck disable=SC1090
source "$STATE_DIR/litellm.env"
set +a
curl -fsS "http://$collector_ip:4000/v1/chat/completions" \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -cn --arg user "$TALLY_TEST_USER" '{model:"tally-free-local",user:$user,messages:[{role:"user",content:"Reply with exactly: Tally connector test OK"}],max_tokens:20}')" \
  >/dev/null

litellm_payload="$(jq -cn --arg key "$LITELLM_MASTER_KEY" '{friendly_name:"LiteLLM Free Local Gateway",interval_seconds:300,paused:false,acknowledge_source_access:true,source_kind:"litellm_api",base_url:"http://127.0.0.1:4000",api_key:$key,initial_backfill_seconds:3600,initial_record_limit:100}')"
litellm_connector_id="$(curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/connectors/schedules" -H 'content-type: application/json' --data-binary "$litellm_payload" | jq -er .connector_instance_id)"
curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/connectors/$litellm_connector_id/sync" >/dev/null

ollama_ip="$("${DOCKER[@]}" inspect tally-ollama --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
scan_preview="$(curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/scans/preview" \
  -H 'content-type: application/json' \
  --data-binary "$(jq -cn --arg target "$ollama_ip/32" '{targets:[$target],exclusions:[],ports:[11434],max_hosts:1,allow_public:false,public_target_authorization:false}')")"
scan_plan="$(jq -c .plan <<<"$scan_preview")"
scan_digest="$(jq -er .scope_digest <<<"$scan_plan")"
curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/scans" \
  -H 'content-type: application/json' \
  -H "idempotency-key: $(openssl rand -hex 16)" \
  --data-binary "$(jq -cn --argjson plan "$scan_plan" --arg digest "$scan_digest" '{plan:$plan,confirm_scope_digest:$digest,authorized_to_scan:true,execution_policy:{concurrency:4,connect_timeout_millis:1500}}')" \
  >/dev/null

if ! "${DOCKER[@]}" inspect tally-k3s >/dev/null 2>&1; then
  "${DOCKER[@]}" volume create tally-k3s-data >/dev/null
  "${DOCKER[@]}" run -d \
    --name tally-k3s \
    --hostname k3s.internal \
    --restart unless-stopped \
    --privileged \
    --network "$TALLY_NETWORK" \
    --network-alias k3s.internal \
    -p 127.0.0.1:6443:6443 \
    -v tally-k3s-data:/var/lib/rancher/k3s \
    rancher/k3s:v1.31.5-k3s1 \
    server --disable traefik --disable servicelb --tls-san k3s.internal --write-kubeconfig-mode 644 \
    >/dev/null
fi
wait_for k3s "${DOCKER[@]}" exec tally-k3s kubectl get --raw=/readyz
"${DOCKER[@]}" exec -i tally-k3s kubectl apply -f - < "$SCRIPT_DIR/kubernetes-fixture.yaml" >/dev/null
k8s_token="$("${DOCKER[@]}" exec tally-k3s kubectl -n kube-system create token tally-discovery --duration=720h)"
k8s_ca="$("${DOCKER[@]}" exec tally-k3s cat /var/lib/rancher/k3s/server/tls/server-ca.crt)"
k8s_payload="$(jq -cn --arg token "$k8s_token" --arg ca "$k8s_ca" '{friendly_name:"Hosted VM k3s Discovery",interval_seconds:300,paused:false,acknowledge_source_access:true,source_kind:"kubernetes_api",api_url:"https://k3s.internal:6443",bearer_token:$token,ca_pem:$ca}')"
k8s_connector_id="$(curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/connectors/schedules" -H 'content-type: application/json' --data-binary "$k8s_payload" | jq -er .connector_instance_id)"
curl -fsS -X POST "$TALLY_BASE_URL/api/v1/tally/connectors/$k8s_connector_id/sync" >/dev/null

printf 'Configured local connectors:\n'
printf '  LiteLLM:    %s\n' "$litellm_connector_id"
printf '  Kubernetes: %s\n' "$k8s_connector_id"
printf 'Native scan authorized for %s:11434\n' "$ollama_ip"
printf 'Inspect findings at %s/api/v1/tally/findings\n' "$TALLY_BASE_URL"
