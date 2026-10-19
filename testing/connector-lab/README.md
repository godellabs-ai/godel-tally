# Connector lab

A disposable Docker environment for exercising every Tally connector against a
running source rather than a fixture.

It brings up a recursive DNS resolver, an Ollama runtime, a LiteLLM gateway
behind TLS, a k3s cluster carrying real AI workloads, a reference MCP server,
and a vendor-shaped mock for the two SaaS control planes that cannot be
self-hosted. One body of genuinely observed DNS traffic is then reshaped into
every source format Tally accepts, so results are comparable across connectors.

This directory is an advanced verification harness. Review the scripts and the
current collector `--help` output before each run; external provider APIs and
their required permissions can change independently of the harness.

## Quick start

```bash
cd testing/connector-lab
bash make-certs.sh
# Populate .env with the variables validated by lab-env.sh. Keep identifiers,
# credentials, and provider keys local; .env is git-ignored.
set -a
source ./.env
set +a
source ./lab-env.sh

cp /etc/hosts hosts.lab
cat >> hosts.lab <<'EOF'
127.0.0.77 api.cloudflare.com
127.0.0.77 api.nextdns.io
127.0.0.78 litellm.lab
EOF

echo '{"nextdns_pages":[{"data":[]}],"casb_integrations":[],
"ai_gateways":[],"ai_gateway_logs":{}}' > payload.json
mkdir -p out
docker compose -f compose.lab.yaml up -d
```

`lab-env.sh` has no credential, account, project, endpoint, or bind defaults. It
reports every missing required variable. Keep `TALLY_HTTP_BIND` identical for
`tallyd` and the collector, because the collector derives its API base from that
value and requires a loopback bind.

## Files

| File | Purpose |
|---|---|
| `compose.lab.yaml` | CoreDNS, Ollama, LiteLLM, Caddy, and the vendor mock |
| `Corefile` | Resolver config; its query log is the DNS evidence |
| `Caddyfile` | TLS front for LiteLLM — Tally refuses a plain-HTTP origin |
| `litellm-config.yaml` | Four model groups: three mapped providers plus one unmapped |
| `k8s-lab.yaml` | Cluster workloads and the minimally scoped read-only RBAC |
| `make-certs.sh` | Lab CA and multi-SAN server certificate |
| `mock_vendor_api.py` | Cloudflare and NextDNS response shapes over real TLS |
| `gen_traffic.py` | Real HTTPS calls to ten AI providers from inside the lab |
| `build_payloads.py` | Resolver log to DNS CSV, Logpush, NextDNS, Zscaler, Palo Alto |
| `test-receiver.sh` | Push receiver matrix for all three push adapters |
| `test-file-adapters.sh` | All sixteen file adapters |
| `lab-env.sh` | Shared environment plus the per-process hosts override |
| `Caddyfile.public` | Reverse-proxy shape for remote viewing — add auth before use |

## Safety

`make-certs.sh` writes a CA private key to `certs/`. Any process started with
`SSL_CERT_FILE` pointing at it trusts everything that key signs, so delete the
directory when a run finishes. `certs/` and every other generated file are
git-ignored.

The hosts override applies inside a private mount namespace created by the
`lab_hosts` helper, so the machine's own `/etc/hosts` is never modified. Confirm
it works before running any Cloudflare or NextDNS pull:

```bash
lab_hosts getent ahosts api.cloudflare.com   # must print 127.0.0.77 only
```

If that prints a real Cloudflare address, stop: the pull would send lab
credentials to the vendor.

## Teardown

```bash
docker compose -f compose.lab.yaml down -v
docker rm -f tally-lab-k3s tally-lab-mcp tally-lab-ollama8080
rm -rf certs out hosts.lab payload.json sa-token.txt k3s-ca.pem
```
