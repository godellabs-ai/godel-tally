import type { EstateRecord } from "./estate";
import { mergeEstatePeople } from "./estate-people";
import { estateForwardNeighbors } from "./estate-relationships";

export type ExposureRisk = "unsanctioned" | "unprotected" | "flagged" | "offline";
export interface EstateJourney { id: string; nodes: EstateRecord[]; edges: EstateRecord[]; risks: ExposureRisk[] }

/** Installed coverage follows a reported device -> agent connection, and the collector's surface. */
export function journeyAgentProtected(path: EstateJourney, agent: EstateRecord) {
  const position = path.nodes.findIndex(node => node.id === agent.id);
  const device = path.nodes.slice(0, position).findLast(node => node.detail.kind === "device");
  if (agent.protection?.state === "protected") return true;
  if (device?.protection?.state !== "protected") return false;
  const collectors = device.protection.collectors;
  return agent.detail.platform === "browser_agent" ? collectors.includes("browser_plugin")
    : ["coding_agent", "sdk_agent"].includes(agent.detail.platform ?? "") && collectors.includes("ggate");
}

/** Forward, cycle-free journeys. Shared services never pull another caller into a path. */
export function estateJourneys(nodes: EstateRecord[], edges: EstateRecord[], limit = 2000) {
  const graph = mergeEstatePeople(nodes, edges);
  const eligible = graph.nodes.filter(node => ["identity", "device", "workload", "agent", "workflow", "mcp_config", "mcp_server", "endpoint", "data_source"].includes(node.detail.kind));
  const links = estateForwardNeighbors(eligible, graph.edges);
  const incoming = new Set([...links.values()].flatMap(items => items.map(item => item.record.id)));
  const visited = new Set<string>(), paths: EstateJourney[] = [];
  let truncated = false;
  function walk(path: EstateRecord[], evidence: EstateRecord[]) {
    if (paths.length >= limit) { truncated = true; return; }
    const node = path.at(-1)!;
    path.forEach(record => visited.add(record.id));
    const next = (links.get(node.id) ?? []).filter(item => !path.some(record => record.id === item.record.id));
    if (next.length && path.length < 24) {
      for (const item of next) { walk([...path, item.record], [...evidence, ...item.edges]); if (truncated) break; }
      return;
    }
    if (next.length) truncated = true;
    const risks: EstateJourney["risks"] = [];
    if (path.some(record => record.sanctioned === false && !["identity", "device"].includes(record.detail.kind))) risks.push("unsanctioned");
    if (path.some(record => record.detail.kind === "device" && record.protection?.state === "unprotected")) risks.push("unprotected");
    if (path.some(record => record.flagged)) risks.push("flagged");
    if (path.some(record => record.protection?.state === "protected" && record.protection.liveness === "offline")) risks.push("offline");
    paths.push({ id: JSON.stringify(path.map(record => record.id)), nodes: path, edges: evidence, risks });
  }
  const roots = eligible.filter(node => node.detail.kind === "identity" || !incoming.has(node.id));
  for (const root of roots) { walk([root], []); if (truncated) break; }
  // A disconnected child-agent cycle still has an inspectable, finite journey.
  if (!truncated) for (const node of eligible) if (!visited.has(node.id)) { walk([node], []); if (truncated) break; }
  return { paths, truncated };
}

