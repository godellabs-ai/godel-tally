# Tally architecture

Tally is a modular Rust service with a Next.js operator console, PostgreSQL control storage and
ClickHouse AI telemetry/inventory. See [AI estate](ai-estate.md) for retention and upgrade details. The design goal is to turn untrusted discovery metadata into minimal, reviewable governance
records while keeping raw source content and connector secrets out of the finding model.

## Runtime topology

```text
cloud, gateway, security, and infrastructure sources
                         |
                         v
        connector worker inside tallyd
              validate and normalize
                         |
                         v
              normalized Observation
                         |
         detect -> resolve -> classify evidence
                         |
                         v
        PostgreSQL                  ClickHouse
   governance and control       AI logs and estate inventory
                         ^
                         |
                    tallyd API
                         ^
                         |
        embedded HTML/JS/CSS console
```

The Native Scanner follows the same normalization path after an operator previews and authorizes a
bounded target plan. It contributes resource-discovery evidence; an open port or discovered runtime
is not counted as a model invocation.

## Runtime components

| Component | Responsibility | Durable state |
| --- | --- | --- |
| `tallyd` | Serves HTTPS, UI, authentication and API; runs migrations, connector jobs and the Gate upgrade runtime | PostgreSQL and ClickHouse |
| `tally-collector` library | Pulls configured sources inside tallyd; optional receiver commands use `tallyd collector` | Connector cursors and run receipts in PostgreSQL |
| `tally-registry` | Lints registry source, generates schemas, and builds or verifies registry artifacts | Files under `registry-data/` |
| `apps/web` | Presents AI inventory, logs, findings, connectors, registry, audit, and settings workflows | Browser state only |
| PostgreSQL | Stores installation state, governance catalog, findings, attribution links, operations, and audit records | Control and governance state |
| ClickHouse | Stores AI-only telemetry and durable estate/coverage aggregates | AI logs, inventory and Tally migration ledger |

## Rust crate boundaries

- `tally-core` owns stable domain and wire contracts. It has no database, HTTP, or connector code.
- `tally-config` loads process configuration and protects secret values from debug output.
- `tally-api` owns HTTP routes and response types, independent of the standalone process wrapper.
- `tally-store-postgres` owns migrations, transactions, query bounds, and durable projections.
- `tally-connectors` converts vendor/source formats into normalized observations.
- `tally-observation-buffer` provides the persistent ClickHouse observation/inventory store and an
  in-memory adapter for isolated tests.
- `tally-detect`, `tally-resolve`, and `tally-risk` turn observations into catalog identities and
  evidence-backed findings.
- `tally-scanner` validates authorized scan scopes and performs registry-defined benign probes.
- `tally-registry` validates source data, local overlays, manifests, and artifact integrity.
- `tally-provenance` verifies digests and provenance metadata.
- `tally-testkit` supplies deterministic fixtures shared across crate tests.

Dependencies point inward toward domain contracts. Process crates under `apps/` compose these
libraries but do not redefine their data model.

## Ingestion lifecycle

1. A configured connector reads a bounded page, file, stream batch, or API response.
2. The connector validates source-specific identifiers, timestamps, limits, and network targets.
3. It emits a normalized `Observation`. Fields for prompt text, response text, documents, request
   bodies, arbitrary headers, cookies, and access tokens do not exist in the durable observation
   contract.
4. Detection and resolution map the observation to registry provider/model identities or an unknown
   identity that requires review.
5. The common admission boundary writes only AI observations and inventory to ClickHouse.
   A PostgreSQL transaction records the ingestion receipt, upserts the unique finding, updates
   first/last-seen time and usage count when appropriate, and links available attribution.
6. Raw source bytes and non-AI logs are discarded. Retained AI telemetry expires independently
   of inventory; retries replay idempotent storage writes before acknowledging source progress.

The unique finding key includes installation, subject identity, reported model version, and evidence
kind. Supporting network evidence can enrich attribution without inflating usage counts.

## Governance model

Provider decisions apply only to that provider. Model decisions apply globally wherever that model
is available. `true` is sanctioned, `false` is unsanctioned, and `null` means the item remains in the
Authorization Queue. Unknown providers and models are never implicitly trusted.

## Trust boundaries

### Connector input

All external source data is untrusted. Connectors enforce response sizes, pagination limits,
identifier bounds, allowlisted endpoint construction, and safe cursor handling. Test fixtures assert
that content-shaped canaries are discarded while permitted attribution survives.

### Credentials

Connector credentials are sealed with ChaCha20-Poly1305 before PostgreSQL persistence. The
installation key comes from `TALLY_SECRET_KEY`, is never committed, and must remain stable for saved
credentials to be decryptable. Rotating it requires re-entering connector credentials.

### Network scanning

Native Scanner requires an explicit authorization acknowledgement, previews a canonical target
plan, rejects unsafe or oversized scopes, and uses bounded registry-defined probes. Operators remain
responsible for scanning only systems they are authorized to test.

### HTTP access

The standalone API supplies CORS and request tracing but no end-user authentication, authorization
middleware, or TLS termination. Loopback is the safe default. Any shared or remote deployment must
place the API and console behind an authenticating TLS proxy and network access controls.

### Browser boundary

Only environment variables prefixed with `NEXT_PUBLIC_` are available to browser code. Secrets and
the internal PostgreSQL URL belong only in server/container environments.

## Storage and retention

PostgreSQL stores normalized catalog entities, sanctions, unique findings, optional attribution,
connector schedules and cursors, scanner jobs, ingestion receipts, and audit records. ClickHouse
retains normalized AI observations for the configured window and keeps estate inventory independently.
Raw source payloads and non-AI logs are discarded. Unclassified cloud flows have a bounded temporary
in-memory correlation window; this pending window is emptied on restart.

The schema is built by ordered, forward-only migrations. See [data-model.md](data-model.md) for the
table-level contract and deletion behavior.

## Build and deployment

`make build` exports Next.js pages, generates the registry, and compiles `tallyd` with
`--features embedded-ui`. UI assets, registry, migrations and baseline documentation are embedded
at compile time. Building with this feature fails if the static UI has not been generated.
The API and UI share a listener. TLS terminates in Rust, so nginx is unnecessary.

`install.sh` downloads a platform archive and verifies its checksum. Native PostgreSQL and
ClickHouse run as separate private instances managed by user services; no existing clusters are
rewritten. Docker and Apple container modes use persistent named database volumes and loopback
ports. Existing mode performs no package installation or database-container lifecycle operations.

Linux uses a systemd user unit; macOS uses launchd. The optional Compose stack contains just
`tallyd`, PostgreSQL and ClickHouse. `make dev` runs one Rust watcher plus Next.js with HTTPS hot
reload; development-only route handlers proxy to the Rust listener. Static export happens in an
isolated staging directory, so building production assets does not rename live development files.

The native public listener replaces forwarded origin headers with `TALLY_URL` before authentication
and CSRF checks. The embedded upgrade bridge checks the Tally session and admin role, permits
only upgrade routes, and never exposes its internal bearer to the browser.

The native deployment described here applies to standalone Tally. Gate continues to run its
Console and embedded Tally modules in Docker. Its router and database topology are unchanged.
Tally-to-Gate upgrades stage that Docker deployment, drain standalone writes, verify the copied
PostgreSQL data, and hand over the HTTPS listener before retiring the standalone application.
