import type { EstateRecord } from "./estate";
import { estateJourneys, journeyAgentProtected, type ExposureRisk } from "./estate-journeys";
import { estateRecordIds } from "./estate";
import type { GovernanceFindingsResponse } from "./tally";

export interface EstateFlowCount { key: string; count: number }
/** Gate events and connector discoveries share a presentation, never a unit of measurement. */
export interface EstateFlowPath {
  user: string; authorization_status: string; agent: string; domain: string; source: string; verdict: string; count: number;
  evidence?: "connector" | "finding";
  findingId?: string;
  /** Stable inventory path identity, for deduplication across pages and connector evidence. */
  discoveryId?: string;
  recordIds?: string[];
  risks?: ExposureRisk[];
  protected?: boolean;
}
export interface EstateEventFlow {
  paths: EstateFlowPath[]; events: number; verdicts: EstateFlowCount[]; truncated: boolean;
}
export const emptyEventFlow: EstateEventFlow = { paths: [], events: 0, verdicts: [], truncated: false };
const runtimeSources = new Set(["godel_gate_runtime", "classification_evidence"]);
export const isConnectorEvidence = (record: EstateRecord) => [record.detail.connector_type, ...(record.detail.evidence_sources ?? [])]
  .some(source => Boolean(source) && !runtimeSources.has(source));
const agentKinds = new Set(["agent", "workflow"]);
const destinationKinds = new Set(["mcp_server", "mcp_config", "endpoint", "data_source"]);

/** Findings survive log retention and may have no agent or estate relationship at all.
 * Use the same saved provider/model decision as the table. A finding's users are associated
 * with its provider/model, not paired with its aggregated agents, hosts or destinations.
 */
export function findingsEventFlow(findings: GovernanceFindingsResponse): EstateEventFlow {
  const rows = new Map([...findings.sanctioned, ...findings.unsanctioned, ...findings.authorization_queue].map(finding => [finding.finding_id, finding]));
  const paths: EstateFlowPath[] = [];
  for (const finding of rows.values()) {
    const users = [...new Set(finding.users.map(user => {
      const name = user.email || user.value;
      return user.email || user.kind === "email" ? name.trim().toLowerCase() : name;
    }))];
    for (const user of users.length ? users : [""]) paths.push({
      evidence: "finding", findingId: finding.finding_id,
      discoveryId: JSON.stringify(["finding", finding.finding_id, user]),
      user, authorization_status: finding.status, agent: "", domain: "Unknown", verdict: "Unknown",
      source: [finding.provider.name, finding.model?.name].filter(Boolean).join(" · "), count: 1,
      risks: finding.status === "unsanctioned" ? ["unsanctioned"] : [],
    });
  }
  return { paths, events: 0, verdicts: [], truncated: false };
}

/** Project recorded connector relationships, not assumed executions or Gate runtime mirrors.
 * People joins use the existing exact-email folding and forward-only traversal. Missing agents,
 * users, destinations, classification and enforcement remain explicit unknowns. A hostname or
 * shared service name alone is never sufficient to attach another person's agent.
 */
export function connectorEventFlow(nodes: EstateRecord[], edges: EstateRecord[], limit = 2000): EstateEventFlow {
  const distinctNodes = [...new Map(nodes.map(node => [node.id, node])).values()];
  const connectorEdges = [...new Map(edges.filter(isConnectorEvidence).map(edge => [edge.id, edge])).values()];
  const connectedIds = new Set(connectorEdges.flatMap(edge => [edge.detail.source, edge.detail.target]));
  const connectorNodes = distinctNodes.filter(node => isConnectorEvidence(node) || connectedIds.has(node.id));
  const journeys = estateJourneys(connectorNodes, connectorEdges, limit);
  const paths = new Map<string, EstateFlowPath>();
  const represented = new Set<string>();
  function add(id: string, user: string, agent: EstateRecord | undefined, source: EstateRecord | undefined, records: EstateRecord[]) {
    const path = { id, nodes: records, edges: [], risks: [] };
    const risks: ExposureRisk[] = [];
    if (records.some(record => record.sanctioned === false && !["identity", "device"].includes(record.detail.kind))) risks.push("unsanctioned");
    if (records.some(record => record.detail.kind === "device" && record.protection?.state === "unprotected")) risks.push("unprotected");
    if (records.some(record => record.flagged)) risks.push("flagged");
    if (records.some(record => record.protection?.state === "protected" && record.protection.liveness === "offline")) risks.push("offline");
    paths.set(id, { discoveryId: id, evidence: "connector", user,
      recordIds: records.flatMap(estateRecordIds), risks, protected: agent ? journeyAgentProtected(path, agent) : false,
      authorization_status: agent?.sanctioned === true ? "sanctioned" : agent?.sanctioned === false ? "unsanctioned" : "authorization_queue",
      agent: agent?.detail.name ?? "", domain: "Unknown", source: source?.detail.name ?? "Unknown", verdict: "Unknown", count: 1 });
  }
  for (const journey of journeys.paths) {
    const actors = journey.nodes.filter(node => agentKinds.has(node.detail.kind));
    const destinations = journey.nodes.filter(node => destinationKinds.has(node.detail.kind));
    if (!actors.length && !destinations.length) continue;
    const user = journey.nodes.find(node => node.detail.kind === "identity")?.detail.name ?? "";
    // Preserve the agent immediately preceding each destination. Do not join models or providers
    // back into an upstream user, and do not cross one agent's private connection into another.
    const routedAgents = new Set<string>();
    for (const source of destinations.length ? destinations : [undefined]) {
      const before = source ? journey.nodes.slice(0, journey.nodes.indexOf(source)) : journey.nodes;
      const agent = before.findLast(node => agentKinds.has(node.detail.kind));
      const ids = (source ? journey.nodes.slice(0, journey.nodes.indexOf(source) + 1) : journey.nodes).map(node => node.id);
      if (agent) { represented.add(agent.id); routedAgents.add(agent.id); }
      add(JSON.stringify(ids), user, agent, source, journey.nodes.filter(node => ids.includes(node.id)));
    }
    // A parent workflow may call a child agent. Keep its reported caller without pretending
    // that the child's destination was directly configured on the parent.
    for (const agent of actors) if (!routedAgents.has(agent.id)) {
      represented.add(agent.id);
      const records = journey.nodes.slice(0, journey.nodes.indexOf(agent) + 1);
      add(JSON.stringify(records.map(node => node.id)), user, agent, undefined, records);
    }
  }
  // Configured agents without an executable connection are still part of connector inventory.
  for (const agent of connectorNodes.filter(node => agentKinds.has(node.detail.kind))) {
    if (!represented.has(agent.id)) add(JSON.stringify([agent.id]), "", agent, undefined, [agent]);
  }
  return { paths: [...paths.values()].slice(0, limit), events: 0, verdicts: [], truncated: journeys.truncated || paths.size > limit };
}

/** Keep exact Gate event/decision totals, while adding independent connector path counts. */
export function combineEventFlows(events: EstateEventFlow | null | undefined, connectors: EstateEventFlow, formatAgent: (name: string) => string = name => name): EstateEventFlow {
  const runtime = events ?? emptyEventFlow;
  const names = new Map<string, string>();
  for (const path of runtime.paths) names.set(formatAgent(path.agent).trim().toLowerCase(), path.agent);
  const discoveries = [...new Map(connectors.paths.map(path => [path.discoveryId, path])).values()].map(path => ({ ...path,
    agent: names.get(path.agent.trim().toLowerCase()) ?? path.agent,
    user: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(path.user.trim()) ? path.user.trim().toLowerCase() : path.user,
  }));
  return { ...runtime, paths: [...runtime.paths, ...discoveries], truncated: runtime.truncated || connectors.truncated };
}
