#!/usr/bin/env bash
# Exercise every file/feed adapter. The DNS-shaped ones get the lab's REAL
# resolver traffic; the cloud ones get the repo's shipped fixtures, because no
# emulator serves Bedrock / Azure OpenAI / Vertex inventory APIs.
set -uo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lab-env.sh"
cd "$TALLY_REPO"
BIN=./target/debug/tally-collector
KEY=testdata/connectors/fixture-pseudonymization-key.hex
TD=testdata/connectors

# run-file prints a descriptor document, then a preview document, then a plain
# trailer line. Decode the JSON stream properly rather than grepping for a key,
# or adapters whose preview uses a different stats shape read as failures.
run() {
  local adapter="$1" file="$2" label="$3"; shift 3
  local connector_instance_id
  connector_instance_id="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  printf '%-24s %-14s ' "$adapter" "$label"
  out=$($BIN run-file --adapter "$adapter" --file "$file" \
      --installation-id "$INSTALLATION_ID" \
      --connector-instance-id "$connector_instance_id" \
      --checkpoint "lab-$adapter-1" --source-lineage-id "lab_$adapter" \
      --pseudonymization-key-file "$KEY" "$@" 2>&1)
  printf '%s' "$out" | python3 -c '
import json, sys

text = sys.stdin.read()
decoder, index, docs = json.JSONDecoder(), 0, []
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    try:
        document, index = decoder.raw_decode(text, index)
    except ValueError:
        break            # the human-readable trailer line
    docs.append(document)

preview = next((d for d in reversed(docs) if "stats" in d), None)
if preview is None:
    print("FAILED: " + " ".join(text.split())[:150])
    sys.exit(0)

stats = preview["stats"]
print("OK  read=%s accepted=%s ignored=%s rejected=%s" % (
    stats.get("records_read"), stats.get("accepted"),
    stats.get("ignored"), stats.get("rejected")))

# The fixtures embed canaries in every field the adapter must discard.
if "ULTRA_SECRET_PROMPT_CANARY" in json.dumps(docs):
    print("    !! REDACTION FAILURE: fixture canary survived into the preview")
'
}

echo "── real lab traffic ─────────────────────────────────────────"
run nextdns            "$LAB/out/nextdns.csv"              "real-dns"
run cloudflare-gateway "$LAB/out/cloudflare-gateway.ndjson" "real-dns"
run zscaler            "$LAB/out/zscaler.ndjson"            "real-dns"
run palo-alto          "$LAB/out/palo-alto.ndjson"          "real-dns"

echo
echo "── shipped fixtures (no self-hostable source exists) ────────"
run aws-managed-ai      "$TD/aws-managed-ai/v1/input.json"      fixture --account-id-env LAB_AWS_ACCOUNT   --region us-east-1
run azure-openai        "$TD/azure-managed-ai/v1/input.json"    fixture --account-id-env LAB_AZURE_SUB     --scope-id-env LAB_AZURE_SCOPE --region eastus
run gcp-vertex-ai       "$TD/gcp-vertex-ai/v1/input.json"       fixture --account-id-env LAB_GCP_PROJECT   --region us-central1
run aws-cloud-flow      "$TD/aws-cloud-flow/v1/input.json"      fixture
run azure-cloud-flow    "$TD/azure-cloud-flow/v1/input.json"    fixture
run gcp-cloud-flow      "$TD/gcp-cloud-flow/v1/input.json"      fixture
run aws-network-mapping "$TD/aws-network-mapping/v1/input.json" fixture
run azure-network-mapping "$TD/azure-network-mapping/v1/input.json" fixture
run gcp-network-mapping "$TD/gcp-network-mapping/v1/input.json" fixture
run cloudflare-casb     "$TD/cloudflare-casb/v1/input.json"     fixture --account-id-env LAB_CF_ACCOUNT
run kubernetes-api      "$TD/kubernetes-api/v1/input.json"      fixture
run litellm             "$TD/litellm/v1/input.json"             fixture
run cloudflare-ai-gateway "$TD/cloudflare-ai-gateway/v1/input.json" fixture
