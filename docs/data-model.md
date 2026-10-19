# Tally data model

PostgreSQL stores Tally control and governance state. ClickHouse stores normalized AI logs and
durable estate inventory. Each store has its own migration series and ledger; see
[AI estate storage and upgrades](ai-estate.md#storage-and-upgrades).

## Migration map

| Migration | Contents |
| --- | --- |
| `postgres/0001_installations.sql` | Installations and sealed secrets |
| `postgres/0002_audit.sql` | Audit log |
| `postgres/0003_ai_catalog.sql` | Provider/model catalog, availability, domains, and sanction defaults |
| `postgres/0004_catalog_seed.sql` | Final provider/model catalog and reviewed service domains |
| `postgres/0005_connectors.sql` | Connector configuration, scheduling, runs, and backfill requests |
| `postgres/0006_ingestion.sql` | Replay-safe ingestion receipts |
| `postgres/0007_findings.sql` | Findings and observation identities |
| `postgres/0008_attribution.sql` | Endpoints, destinations, users, clients, workloads, and finding links |
| `postgres/0009_scanner_jobs.sql` | Authorized scanner plans and runs |
| `postgres/0010_registry_overlays.sql` | Local registry overlays and their audit |
| `postgres/0011_estate_reviews.sql` | Installation-scoped inventory decisions |
| `postgres/0012_sample_workspace.sql` | Sample workspace tracking |
| `clickhouse/0001_ai_events.sql` | Retained AI events and their activity index |
| `clickhouse/0002_estate.sql` | Durable estate inventory |
| `clickhouse/0003_endpoint_coverage.sql` | Endpoint coverage denominator |
| `apps/tallyd/migrations/0001_auth.sql` | Standalone users, invitations, sessions, and password resets |
| `apps/tallyd/migrations/0002_email.sql` | Standalone email configuration |

Related tables, indexes, functions, and defaults stay together. The files run in numeric order;
each creates its final schema without replaying the historical alteration/backfill sequence.

The October 2026 baseline requires empty databases. It replaces the historical migration series;
existing ledgers and old database dumps are not upgrade inputs. Subsequent changes must use new
numbered migrations. SQLx validates checksums; do not truncate the ledger to bypass a mismatch.
Gate applies Tally first, then its own schema and seeds. Gate owns the MCP extension of findings.

AI logs expire by `expires_at`; aggregate inventory has no log TTL.

## Catalog and governance

Providers and models default to unsanctioned. `tally_default_provider_sanction` defines the
enterprise exceptions: OpenAI, Anthropic, Google/Gemini and Vertex AI, Microsoft/Azure and
Microsoft 365 Copilot, GitHub Copilot, Amazon Bedrock, Cohere, Mistral, Databricks, Snowflake,
and IBM watsonx. Exceptions apply to matching catalog entries and their catalogued models;
providers without reviewed service domains are not actionable registry entries. Discovered
models start unsanctioned. Resetting registry decisions restores these same defaults.
Coding/SDK agent decisions and MCP decisions belong to Gate and are unchanged by this reset.

- `ai_providers` represents APIs, cloud AI platforms, gateways, and local runtimes.
- `ai_models` represents globally governed model families and releases.
- `ai_provider_models` records the providers through which each model is available or observed.
- Local overlays extend the built-in registry without mutating the signed base artifact.

Provider sanctions apply to one provider. Model sanctions apply globally.

## Findings and evidence

A finding is unique within an installation by its governed subject, reported model version, and
evidence kind.

Evidence kinds keep different claims separate:

- `ai_usage` means a connector recognized a bounded AI request signature;
- `network_activity` means network evidence reached a recognized AI service;
- `resource_discovery` means a managed or local runtime/resource was discovered.

Repeated primary observations update first/last-used timestamps and a count instead of creating raw
event rows. Supporting observations can add attribution without inflating the usage count.
`ingestion_batches` and observation links make retries idempotent.

## Attribution

Context is normalized into optional foreign-key relationships:

- `endpoint_hosts` and `finding_hosts` identify source devices or hosts running a local service;
- `destination_hosts` and `finding_destinations` identify remote provider or gateway targets;
- `endpoint_users` and `finding_users` identify an email, source username, or source-native ID;
- `finding_connectors` identifies every connector that contributed evidence; and
- `finding_workloads` identifies bounded Kubernetes namespace, workload, kind, and runtime image
  fields.
- `finding_clients` identifies an allowlisted request client/framework and, when explicitly
  supplied, a bounded agent ID, with connector lineage and first/last-seen timestamps. Raw
  user-agent strings, headers, request tags and arbitrary metadata have no storage columns.

A relationship is absent when the connector did not supply it. Tally does not infer a user from an
IP address or a destination from a provider name.
Client/framework hints are source-reported attribution, not proof of a running agent process.

## Operations and audit

- `connector_states`, `connector_jobs`, and `connector_runs` manage source configuration,
  schedules, cursors, and outcomes.
- `connector_backfill_requests` records bounded replay requests and their idempotency receipts.
- `scan_jobs` stores authorized Native Scanner plans and status.
- `audit_log` stores administrative and operational changes.
- `installations` and `installation_secrets` provide installation scope and credential protection.

Connector credential ciphertext and nonces are durable; plaintext credentials are not. The
installation key remains outside PostgreSQL in `TALLY_SECRET_KEY`.

## Retention and deletion

Raw source payloads and non-AI logs are not retained. Normalized AI observations are stored in
ClickHouse with configurable retention, independently of the durable estate inventory. Data-removal operations can
delete selected operational categories and can apply a time cutoff where the schema supports it.
Deletion is permanent and is recorded in the audit log.

Migrations are forward-only. Add a new numbered migration for schema changes instead of editing a
migration that may already have been applied.
