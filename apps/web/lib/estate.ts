export interface EstateRecord {
  id: string;
  record_type: "node" | "edge";
  first_seen: number;
  last_seen: number;
  detail: {
    kind: string; name: string; source: string | null; target: string | null;
    platform: string | null; state: string | null; confidence: string; basis: string;
    connector_id: string; connector_type: string; observation_id: string;
    registry_entry_id: string | null; hostname: string | null; source_ip: string | null;
    model: string | null; process_id: string | null; parent_process_id: string | null;
    region: string | null; identity_kind: string | null; config_file: string | null;
    port?: number | null; namespace?: string | null; workload_kind?: string | null;
    runtime_image?: string | null; model_family?: string | null; model_catalog_key?: string | null; model_owner?: string | null;
    country_code?: string | null; modalities?: string[] | null; capabilities?: string[] | null;
    model_providers?: string[] | null; evidence_sources?: string[] | null;
    additional_source_ips?: string[] | null;
  };
  sanctioned?: boolean | null;
  flagged?: boolean;
  review_sanctioned?: boolean | null;
  registry_id?: string | null;
  /** A host registry owns this decision; Tally reviews can still flag the entity. */
  decision_managed?: boolean;
  /** Supplied only by an embedding host with an installed-collector registry. */
  protection?: { state: "protected" | "unprotected" | "unknown"; collectors: string[]; reason: string; liveness?: "online" | "offline" | "unknown" };
  /** Directory membership supplied by a host or connector using an explicit identity join. */
  teams?: Array<{ id: string; name: string; source: string }>;
  /** Source identity IDs folded into one person for graph and inventory presentation. */
  identityRecordIds?: string[];

}

export function estateRecordIds(record: EstateRecord) { return record.identityRecordIds ?? [record.id]; }

export interface EstateResponse {
  records: EstateRecord[];
  next_cursor: string | null;
  coverage: { endpoint_devices_30d?: number; scope: string; limits: string[] };
}
export interface EstateActivity {
  days: number; since: number; until: number; scope: string;
  summary: {
    records: number; requests: number; byte_reports: number; sent_reports: number; received_reports: number; bytes_sent: number; bytes_received: number;
    first_seen: number | null; last_seen: number | null;
    daily: Array<{ day: number; records: number; requests: number; byte_reports: number; sent_reports: number; received_reports: number; bytes_sent: number; bytes_received: number }>;
  };
}
export function relativeSeen(time: number) {
  const minutes = Math.max(0, Math.floor((Date.now() - time) / 60000));
  return minutes < 1 ? "just now" : minutes < 60 ? `${minutes}m ago` : minutes < 1440 ? `${Math.floor(minutes / 60)}h ago` : `${Math.floor(minutes / 1440)}d ago`;
}
export function formatBytes(value: number) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = value > 0 ? Math.min(4, Math.floor(Math.log(value) / Math.log(1024))) : 0;
  return `${(value / 1024 ** index).toLocaleString(undefined, { maximumFractionDigits: index ? 1 : 0 })} ${units[index]}`;
}
export function entityStatus(record: EstateRecord) { return record.sanctioned === true ? "Sanctioned" : record.sanctioned === false ? "Unsanctioned" : "Unreviewed"; }
export type EstateReviewAction = "sanction" | "unsanction" | "clear_sanction" | "flag" | "clear_flag";
/** Which review decisions this record accepts. Host-managed and identity-like records can only be flagged. */
export function estateReviewOptions(record: EstateRecord) {
  const sanction = !record.decision_managed && (["agent", "workflow", "mcp_server", "mcp_config", "endpoint", "workload"].includes(record.detail.kind) || Boolean(record.registry_id));
  return { sanction, clear: sanction && !record.registry_id && record.review_sanctioned != null };
}
export function entityKind(kind: string) { return ({ data_category: "Data category", data_source: "Data source", identity: "Identity", device: "Device", agent: "AI agent", mcp_server: "MCP server", mcp_config: "MCP configuration", endpoint: "Endpoint", provider: "Provider", model: "Model", workload: "Workload", workflow: "AI workflow" } as Record<string,string>)[kind] ?? kind; }
