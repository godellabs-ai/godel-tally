import { formatDateTime } from "./datetime";
export interface EventWorkload {
  namespace_name?: string; workload_name?: string; workload_kind?: string; runtime_image?: string;
}
export interface EventObservation {
  observation_id: string;
  observed_at: string;
  received_at: string;
  kind: string;
  connector: { instance_id: string; connector_type: string; source_lineage_id?: string };
  actor?: {
    hostname?: string; source_ip?: string; additional_source_ips?: string[]; device_key?: string;
    identity?: { email?: string; source_subject?: string; source_subject_kind?: string; subject_key?: string; display_label?: string; authority?: string };
    request_client?: { name?: string; agent_id?: string }; workload?: EventWorkload;
  };
  destination?: { host?: string; ip?: string; port?: number; path_prefix?: string };
  service?: { declared_model_id?: string; tls_server_name?: string; vendor_application_id?: string; ai_request?: boolean };
  network?: { protocol?: string; source_port?: number; destination_port?: number; bytes_sent?: number; bytes_received?: number; request_count?: number; direction?: string };
  cloud?: { provider?: string; provider_service?: string; region?: string; resource_kind?: string; lifecycle_state?: string; usage_kind?: string };
  workload?: EventWorkload;
  process?: { executable?: string; pid?: string; unique_id?: string; started_at?: string; parent_executable?: string; parent_pid?: string; parent_unique_id?: string };
  inventory?: { user_role?: string; device_key_kind?: string };
  agent?: { name?: string; platform?: string; kind?: string; process_id?: string; parent_name?: string; attribution_confidence?: string; attribution_basis?: string };
  saas?: { capability_state?: string; sanction_status?: string };
  outcome?: { action?: string; result?: string; response_code?: string };
  source?: { type: string; source_record_id?: string; probe_id?: string };
}
export const authorizationFilters = [
  { value: "all", label: "All" },
  { value: "unsanctioned", label: "Unsanctioned" },
  { value: "authorization_queue", label: "Authorization Queue" },
  { value: "sanctioned", label: "Sanctioned" },
] as const;
export type EventAuthorizationStatus = typeof authorizationFilters[number]["value"];
export type EventStatus = Exclude<EventAuthorizationStatus, "all">;
export interface EventRegistryEntity { id: string; name: string; key: string; sanctioned: boolean | null }
export interface EventFindingContext {
  observation_id: string; finding_id: string; evidence_kind: string; status: EventStatus;
  provider: EventRegistryEntity; model: EventRegistryEntity | null; model_version: string | null;
}
export interface EventStreamResponse {
  items: EventObservation[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  snapshot: number;
  sources: Array<{ connector_id: string; label: string }>;
  findings: EventFindingContext[];
}
export interface EventRow { event: EventObservation; findings: EventFindingContext[]; connector: string }
export const eventKinds = ["agent_activity", "dns_query", "http_metadata", "network_flow", "network_mapping", "scan_fingerprint", "cloud_resource", "cloud_usage", "saas_capability", "kubernetes_resource", "registry_pull", "connector_health"];
const labels: Record<string, string> = {
  http_metadata: "HTTP activity", dns_query: "DNS lookup", network_flow: "Network traffic", network_mapping: "Network mapping",
  agent_activity: "Agent activity", cloud_resource: "Resource discovered", cloud_usage: "Cloud activity", scan_fingerprint: "Service discovered",
  saas_capability: "AI capability", kubernetes_resource: "Workload discovered", registry_pull: "Image pulled", connector_health: "Connector health",
  langchain: "LangChain", langgraph: "LangGraph", opencode: "OpenCode", claude_code: "Claude Code", codex: "Codex", cursor: "Cursor",
  openai_python: "OpenAI Python SDK", openai_node: "OpenAI Node SDK", curl: "curl", aws: "AWS", gcp: "Google Cloud", azure: "Azure",
  aws_bedrock: "Amazon Bedrock", aws_sagemaker: "Amazon SageMaker", azure_openai: "Azure OpenAI", azure_ai_foundry: "Azure AI Foundry", gcp_vertex_ai: "Vertex AI",
};
export const eventLabel = (value: string) => labels[value] ?? value.replaceAll("_", " ").replace(/^./, char => char.toUpperCase());
export const unique = (values: (string | undefined | null)[]) => [...new Set(values.filter((value): value is string => Boolean(value)))];
export const eventStatus = (row: EventRow): EventStatus => row.findings.some(f => f.status === "unsanctioned") ? "unsanctioned" : !row.findings.length || row.findings.some(f => f.status === "authorization_queue") ? "authorization_queue" : "sanctioned";
export const eventPerson = (event: EventObservation) => event.actor?.identity?.email ?? event.actor?.identity?.source_subject ?? event.actor?.identity?.display_label;
export const sourceAddresses = (event: EventObservation) => unique([event.actor?.source_ip, ...(event.actor?.additional_source_ips ?? [])]);
export const eventDestination = (event: EventObservation) => event.destination?.host ?? event.service?.tls_server_name ?? event.destination?.ip;
export const eventProviders = (row: EventRow) => unique(row.findings.map(f => f.provider.name));
export const eventModels = (row: EventRow) => row.event.kind === "network_flow" && !row.event.service?.declared_model_id ? [] : unique([...row.findings.map(f => f.model?.name), ...(!row.findings.some(f => f.model) ? [row.event.service?.declared_model_id] : [])]);
export function eventActivity(row: EventRow) {
  const event = row.event;
  if (["cloud_resource", "kubernetes_resource", "scan_fingerprint", "saas_capability", "network_mapping", "registry_pull", "connector_health"].includes(event.kind)) return eventLabel(event.kind);
  if (event.service?.ai_request || row.findings.some(f => f.evidence_kind === "ai_usage")) return "AI request";
  return eventLabel(event.kind);
}
export function authorizationReason(row: EventRow) {
  const rejected = unique(row.findings.flatMap(f => [f.provider.sanctioned === false ? f.provider.name : null, f.model?.sanctioned === false ? f.model.name : null]));
  if (rejected.length) return `${rejected.join(", ")} ${rejected.length === 1 ? "is" : "are"} marked unsanctioned in AI Registry.`;
  if (!row.findings.length) return "This event has no linked provider or model decision yet. Review the destination and source evidence to identify the AI service.";
  if (eventStatus(row) === "authorization_queue") return "A linked provider or model is awaiting an authorization decision in AI Registry.";
  return "The linked provider and model decisions permit this usage in AI Registry.";
}
export function eventHandoff(row: EventRow) {
  const e = row.event;
  return ["AI activity investigation", `Authorization: ${authorizationFilters.find(f => f.value === eventStatus(row))!.label}`, authorizationReason(row),
    `Observed: ${formatDateTime(e.observed_at)} (${e.observed_at})`, `Person: ${eventPerson(e) ?? "Not identified by source"}`,
    `Hostname: ${e.actor?.hostname ?? "Not reported"}`, `Source IP: ${sourceAddresses(e).join(", ") || "Not reported"}`,
    `AI provider: ${eventProviders(row).join(", ") || "Not identified"}`, `Model: ${eventModels(row).join(", ") || "Not reported"}`,
    `Destination: ${eventDestination(e) ?? "Not reported"}${e.destination?.port ? `:${e.destination.port}` : ""}`,
    `Activity: ${eventActivity(row)}`, `Connector: ${row.connector}`, `Source action: ${e.outcome?.action ?? "Not reported"}`,
    `Source result: ${e.outcome?.result ?? "Not reported"}`, `Event ID: ${e.observation_id}`,
    ...(e.source?.source_record_id ? [`Source record ID: ${e.source.source_record_id}`] : []),
    "Review with the device, network, or application owner. Enforcement is performed in the external system.",
  ].join("\n");
}
