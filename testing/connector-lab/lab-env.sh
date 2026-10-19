# Shared lab environment. Source this before running any Tally binary.
export LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The lab lives at <repo>/testing/connector-lab, so the checkout is two levels up.
export TALLY_REPO="$(cd "$LAB/../.." && pwd)"

require_lab_env() {
  local name="$1"
  if ! declare -p "$name" >/dev/null 2>&1; then
    printf 'Required connector-lab environment variable is not set: %s\n' "$name" >&2
    return 1
  fi
  if [[ -z "${!name}" ]]; then
    printf 'Required connector-lab environment variable is not set: %s\n' "$name" >&2
    return 1
  fi
  export "$name"
}

# Keep credentials and deployment-specific identifiers in a local, git-ignored
# environment file. Nothing sensitive is assigned a repository default.
for name in \
  TALLY_HTTP_BIND \
  TALLY_API_URL \
  TALLY_POSTGRES_URL \
  TALLY_SECRET_KEY \
  LITELLM_MASTER_KEY \
  OPENAI_API_KEY \
  ANTHROPIC_API_KEY \
  GEMINI_API_KEY \
  TALLY_LITELLM_BASE_URL \
  TALLY_KUBERNETES_API_URL \
  TALLY_CLOUDFLARE_ACCOUNT_ID \
  TALLY_CLOUDFLARE_API_TOKEN \
  TALLY_CLOUDFLARE_ANALYTICS_TOKEN \
  TALLY_CLOUDFLARE_AI_GATEWAY_TOKEN \
  TALLY_NEXTDNS_API_KEY \
  TALLY_RECEIVER_AUTHORIZATION; do
  require_lab_env "$name" || return 1
done

# Tally and the lab gateway must use the same caller-supplied LiteLLM key.
export TALLY_LITELLM_API_KEY="$LITELLM_MASTER_KEY"

# Derived from the running installation; do not hand-write it.
if ! declare -p INSTALLATION_ID >/dev/null 2>&1 || [[ -z "$INSTALLATION_ID" ]]; then
  INSTALLATION_ID="$(docker exec godel-tally-postgres-1 \
    psql -U tally -d tally -t -A -c 'select installation_id from installations limit 1;' 2>/dev/null)"
fi
if [[ -z "$INSTALLATION_ID" ]]; then
  printf 'Could not derive INSTALLATION_ID from the running Tally database\n' >&2
  return 1
fi
export INSTALLATION_ID
# The daemon holds the only registry; the CLI no longer takes a bundle.

# Lab CA, so the collector's real rustls client can verify the locally hosted
# vendor endpoints. rustls-platform-verifier reads the system store, which
# rustls-native-certs sources from SSL_CERT_FILE on Linux.
export SSL_CERT_FILE="$LAB/certs/ca.pem"

# The schedule-* commands read connector credentials once, seal them under
# TALLY_SECRET_KEY, and store the ciphertext; the worker never reads this
# environment at poll time.
export TALLY_KUBERNETES_CA_FILE="$LAB/k3s-ca.pem"

# Run a command with the lab's private /etc/hosts, so api.cloudflare.com and
# api.nextdns.io resolve to the local mock instead of the real vendor. This is a
# per-process mount namespace: nothing on the machine is modified.
lab_hosts() {
  unshare --mount --map-root-user --user -- \
    bash -c "mount --bind '$LAB/hosts.lab' /etc/hosts && exec \"\$@\"" _ "$@"
}
