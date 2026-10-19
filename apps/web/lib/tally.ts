export interface TallyOverviewSummary {
  providers_observed: number;
  models_observed: number;
  unsanctioned: number;
  authorization_queue: number;
  sanctioned: number;
  users: number;
  hosts: number;
  connectors: number;
  last_used_at: string | null;
}

export interface RegistryProvider {
  provider_id: string;
  key: string;
  name: string;
  category: "direct_provider" | "managed_platform" | "ai_gateway" | "local_runtime" | "inference_server" | "enterprise_application";
  country_code: string | null;
  catalog: boolean;
  sanctioned: boolean | null;
  model_count: number;
  finding_count: number;
  last_used_at: string | null;
}

export interface RegistryModel {
  model_id: string;
  key: string;
  name: string;
  family: string;
  country_code: string | null;
  modalities: string[];
  capabilities: string[];
  catalog: boolean;
  sanctioned: boolean | null;
  provider_ids: string[];
  provider_names: string[];
  finding_count: number;
  last_used_at: string | null;
}

export interface GovernanceFinding {
  finding_id: string;
  status: "unsanctioned" | "authorization_queue" | "sanctioned";
  violation_reasons: string[];
  evidence_kind: "ai_usage" | "network_activity" | "resource_discovery";
  provider: RegistryProvider;
  model: RegistryModel | null;
  model_version: string | null;
  first_used_at: string;
  last_used_at: string;
  usage_count: number;
  endpoints: Array<{
    endpoint_host_id: string;
    kind: "hostname" | "ip_address";
    value: string;
    role: "source" | "local_service";
    port: number | null;
    first_seen: string;
    last_seen: string;
  }>;
  destinations: Array<{
    destination_host_id: string;
    kind: "hostname" | "ip_address";
    value: string;
    port: number | null;
    first_seen: string;
    last_seen: string;
  }>;
  users: Array<{
    endpoint_user_id: string;
    kind: "email" | "user_name" | "source_user_id";
    value: string;
    email: string | null;
    first_seen: string;
    last_seen: string;
  }>;
  connectors: Array<{
    connector_instance_id: string;
    name: string;
    connector_type: string;
    first_seen: string;
    last_seen: string;
  }>;
  workloads: Array<{
    namespace_name: string;
    workload_name: string;
    workload_kind: "deployment" | "stateful_set" | "daemon_set" | "job" | "cron_job" | "pod" | "service" | "node";
    runtime_image: string | null;
    first_seen: string;
    last_seen: string;
  }>;
  clients?: Array<{
    name: "langchain" | "langgraph" | "opencode" | "cursor" | "claude_code" | "codex" | "openai_python" | "openai_node" | "curl" | null;
    agent_id: string | null;
    connector_instance_id: string;
    first_seen: string;
    last_seen: string;
  }>;
}

export interface GovernanceFindingsResponse {
  unsanctioned: GovernanceFinding[];
  authorization_queue: GovernanceFinding[];
  sanctioned: GovernanceFinding[];
}

export interface ConnectorState {
  sample?: boolean;
  connector_instance_id: string;
  connector_type: string;
  display_name: string;
  friendly_name: string | null;
  implementation_version: string;
  transport: string;
  health: "never_run" | "healthy" | "delayed" | "error" | "paused";
  cursor_value: string;
  last_success_at: string | null;
  last_poll_at: string | null;
  last_source_at: string | null;
  lag_seconds: number | null;
  records_read_total: number;
  accepted_total: number;
  ignored_total: number;
  rejected_total: number;
  deduplicated_total: number;
  last_error_code: string | null;
  redaction_digest: string | null;
  descriptor: Record<string, unknown>;
}

export interface ConnectorJob {
  job_id: string;
  connector_instance_id: string;
  mode: string;
  status: "enabled" | "paused";
  schedule_seconds: number | null;
  next_run_at: string | null;
  leased: boolean;
  lease_until: string | null;
  source_reference_kind: string | null;
  source_reference: string | null;
  privacy: { credentials_sealed: boolean; plaintext_secret_stored: false; content_retained: false };
  attempt_count: number;
  consecutive_failures: number;
  last_started_at: string | null;
  last_finished_at: string | null;
  last_outcome: "completed" | "duplicate" | "failed" | "cancelled" | null;
  last_error_code: string | null;
  updated_at: string;
}

export interface ConnectorStatesResponse { items: ConnectorState[]; jobs: ConnectorJob[] }
export interface ConnectorConfigurationResponse { fields: Record<string, string>; credential_reentry_required: boolean }
export interface ConnectorSyncResponse { requested_at: string; job: ConnectorJob; content_retained: false }
export interface ConnectorSyncSweepResponse { requested_at: string; triggered: number; skipped_leased: number; skipped_paused: number; jobs: ConnectorJob[]; content_retained: false }
export interface ConnectorDeleteResponse { connector_instance_id: string; connector_type: string; display_name: string; friendly_name: string | null; job_id: string | null; schedule_deleted: boolean; runs_deleted: number; ingestion_batches_deleted: number; deleted_at: string }

export interface AuditResponse {
  items: Array<{ audit_id: string; at: string; actor: string; action: string; entity_type: string; entity_id: string; detail: Record<string, unknown> }>;
}
export type AuditEvent = AuditResponse["items"][number];

export interface ScanPlan { version: string; targets: string[]; ports: number[]; host_count: number; probe_count: number; allow_public: boolean; public_target_authorization: boolean; scope_digest: string }
export interface ScanPreview { plan: ScanPlan; requested_targets: string[]; skipped: Array<{ name: string; address: string; reason: string }>; discovered_local_scope: boolean; sends_network_traffic: false; content_retained: false }
export interface ScanJob {
  scan_id: string;
  scope_digest: string;
  plan: ScanPlan;
  execution_policy: { concurrency: number; connect_timeout_millis: number };
  status: "planned" | "running" | "cancel_requested" | "completed" | "cancelled" | "failed";
  authorized_by: string;
  authorization_acknowledged_at: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  planned_probes: number;
  completed_probes: number;
  open_port_count: number;
  fingerprint_attempt_count: number;
  fingerprint_match_count: number;
  resolved_system_count: number;
  results: Array<{ address: string; port: number; state: "open" | "closed" | "timed_out" | "unreachable" | "cancelled" | "error"; duration_millis: number }>;
  error_code: string | null;
  content_retained: false;
}
export interface ScanJobsResponse { items: ScanJob[] }

export type ImportAdapter = "openai_agents" | "claude_agents" | "gemini_agents" | "defender_stream" | "servicenow_agents" | "n8n_agents" | "nextdns" | "cloudflare_gateway" | "zscaler" | "palo_alto" | "aws_managed_ai" | "azure_openai" | "azure_ai_foundry" | "gcp_vertex_ai" | "aws_cloud_flow" | "aws_network_mapping" | "azure_cloud_flow" | "azure_network_mapping" | "gcp_cloud_flow" | "gcp_network_mapping" | "cloudflare_casb" | "kubernetes_api" | "litellm" | "cloudflare_ai_gateway";
export interface ImportPreviewResponse {
  descriptor: { connector_type: string; display_name: string; source_vendor: string; source_product: string; transport: string; required_permissions: string[]; requested_fields: string[]; prohibited_fields: string[]; privacy_contract: string };
  records_read: number;
  accepted: number;
  ignored: number;
  rejected: number;
  connector_instance_id: string;
  canonical_digest: string;
  observation_count: number;
  redaction: { pseudonymization: string; discarded_fields: string[]; source_bytes_retained: false };
  samples: Array<{ observed_at: string; kind: string; destination: string | null; actor: string | null; outcome: string | null }>;
  writes_data: false;
  source_bytes_retained: false;
  content_retained: false;
}
export interface ImportCommitResponse { run_id: string; batch_id: string; disposition: "accepted" | "retry" | "duplicate"; status: "completed" | "duplicate"; accepted: number; deduplicated: number; findings_updated: number; canonical_digest: string; content_retained: false }

export interface DataInventory { ai_logs: number; inventory_entities: number; findings: number; endpoint_hosts: number; destination_hosts: number; endpoint_users: number; connectors: number; connector_runs: number; ingestion_receipts: number; scanner_runs: number; audit_events: number; registry_sanctions: number }
export type TallyMutationResult<T> = { ok: true; data: T } | { ok: false; error: string };

export function connectorLabel(connector: Pick<ConnectorState, "display_name" | "friendly_name">) { return connector.friendly_name?.trim() || connector.display_name; }
export function getOverviewSummary(cookie?: string) { return getTallyJson<TallyOverviewSummary>("/overview", cookie); }
export function getRegistryProviders(cookie?: string) { return getTallyJson<RegistryProvider[]>("/registry/providers", cookie); }
export function getProviderDomains(cookie?: string) { return getTallyJson<Record<string, string[]>>("/registry/provider-domains", cookie); }
export function getRegistryModels(cookie?: string) { return getTallyJson<RegistryModel[]>("/registry/models", cookie); }
export function getGovernanceFindings(cookie?: string) { return getTallyJson<GovernanceFindingsResponse>("/findings", cookie); }
export function getTallyConnectors(cookie?: string) { return getTallyJson<ConnectorStatesResponse>("/connectors", cookie); }
export function getTallyAudit(cookie?: string) { return getTallyJson<AuditResponse>("/audit", cookie); }
export function getTallyScans(cookie?: string) { return getTallyJson<ScanJobsResponse>("/scans", cookie); }
export function getDataInventory(cookie?: string) { return getTallyJson<DataInventory>("/data", cookie); }
export function getConnectorConfiguration(id: string) { return getTallyJson<ConnectorConfigurationResponse>(`/connectors/${encodeURIComponent(id)}/configuration`); }

export function scheduleConnector(payload: unknown): Promise<TallyMutationResult<ConnectorJob>> {
  return mutateTallyJson<ConnectorJob>("/connectors/schedules", payload);
}
export function syncConnector(id: string) { return mutateTally<ConnectorSyncResponse>(`/connectors/${encodeURIComponent(id)}/sync`, "POST"); }
export function syncAllConnectors() { return mutateTally<ConnectorSyncSweepResponse>("/connectors/sync", "POST"); }
export function deleteConnector(id: string) { return mutateTally<ConnectorDeleteResponse>(`/connectors/${encodeURIComponent(id)}`, "DELETE"); }
export function setRegistrySanction(kind: "provider" | "model", ids: string[], sanctioned: boolean) {
  return setRegistrySanctions(kind === "provider" ? ids : [], kind === "model" ? ids : [], sanctioned);
}
export function setRegistrySanctions(providerIds: string[], modelIds: string[], sanctioned: boolean) {
  return mutateTallyJson<{ affected: number }>("/registry/sanctions", { provider_ids: providerIds, model_ids: modelIds, sanctioned });
}
export function deleteTallyData(request: { confirmation: string; scopes: string[]; before: string | null }) { return mutateTallyJson<DataInventory>("/data/delete", request); }

async function getTallyJson<T>(path: string, cookie?: string): Promise<T | null> {
  try {
    const response = await tallyFetch(path, { cache: "no-store", signal: AbortSignal.timeout(15_000), headers: cookie ? { cookie } : undefined });
    return response.ok ? (await response.json()) as T : null;
  } catch { return null; }
}

async function mutateTally<T>(path: string, method: "POST" | "DELETE"): Promise<TallyMutationResult<T>> {
  try {
    const response = await tallyFetch(path, { method, cache: "no-store" });
    if (!response.ok) return { ok: false, error: await problemMessage(response) };
    return { ok: true, data: (await response.json()) as T };
  } catch (error) { return { ok: false, error: error instanceof Error ? error.message : "Could not reach the Tally API." }; }
}

async function mutateTallyJson<T>(path: string, body: unknown): Promise<TallyMutationResult<T>> {
  try {
    const response = await tallyFetch(path, { method: "POST", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) return { ok: false, error: await problemMessage(response) };
    return { ok: true, data: (await response.json()) as T };
  } catch (error) { return { ok: false, error: error instanceof Error ? error.message : "Could not reach the Tally API." }; }
}

const problemMessages: Record<string, string> = {
  sample_connector_read_only: "Evaluation connectors are inactive and cannot connect to live sources. Add a separate connection for your environment.",
  sample_removal_in_progress: "Evaluation data removal is incomplete. Finish removing it before adding a new evaluation workspace.",
  connector_delete_blocked: "A connector is still enforcing a blocklist in its vendor account, so nothing was deleted. Turn off enforcement for that connector, wait for its rules to be removed, and try again.",
};

async function problemMessage(response: Response) {
  const body = (await response.text()).trim();
  try { const problem = JSON.parse(body) as { code?: string; title?: string }; const known = problem.code ? problemMessages[problem.code] : undefined; if (known) return known; if (problem.title) return problem.title.replaceAll("_", " "); } catch { /* use safe response text */ }
  return body.length ? body.slice(0, 300) : `Tally rejected this request (${response.status}).`;
}

/** Fetches a Tally path and forwards a host application's bearer token when one is present. */
export function tallyFetch(path: string, init: RequestInit = {}) {
  const token = typeof window !== "undefined" ? window.localStorage.getItem("auth_token") : null;
  const headers = new Headers(init.headers);
  if (token && !headers.has("authorization")) headers.set("authorization", `Bearer ${token}`);
  return fetch(`${tallyApiBase()}${path}`, { ...init, headers });
}

function tallyApiBase() {
  if (typeof window !== "undefined") return "/api/v1/tally";
  return process.env.TALLY_API_INTERNAL_URL || "http://127.0.0.1:8788/api/v1/tally";
}

export interface SampleDataStatus {
  present: boolean; state: "absent" | "adding" | "ready" | "partial" | "removing";
  created_at: string | null; counts: DataInventory; connector_types: string[]; categories: string[]; observation_kinds: string[];
}
export function getSampleData() { return getTallyJson<SampleDataStatus>("/data/sample"); }
export function addSampleData() { return mutateTallyJson<SampleDataStatus>("/data/sample", {}); }
export function removeSampleData() { return mutateTallyJson<SampleDataStatus>("/data/sample/delete", { confirmation: "delete evaluation data" }); }
export function previewTallyData(request: { scopes: string[]; before: string | null }) { return mutateTallyJson<DataInventory>("/data/preview", request); }
