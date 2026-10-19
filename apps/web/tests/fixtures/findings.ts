import type { GovernanceFinding, GovernanceFindingsResponse } from "../../lib/tally";

export function findingsFixture(): GovernanceFindingsResponse {
  const finding = (id: string, name: string, status: GovernanceFinding["status"]): GovernanceFinding => ({
    finding_id: id, status, violation_reasons: [], evidence_kind: "ai_usage",
    provider: { provider_id: id, key: name.toLowerCase(), name, category: "direct_provider", country_code: null, catalog: true,
      sanctioned: status === "authorization_queue" ? null : status === "sanctioned", model_count: 0, finding_count: 1, last_used_at: null },
    model: null, model_version: null, first_used_at: new Date().toISOString(), last_used_at: new Date().toISOString(), usage_count: 5,
    endpoints: [], destinations: [], users: [], connectors: [], workloads: [], clients: [],
  });
  return { sanctioned: [finding("approved", "Approved AI", "sanctioned")], unsanctioned: [finding("unapproved", "Unapproved AI", "unsanctioned")], authorization_queue: [finding("pending", "Pending AI", "authorization_queue")] };
}
