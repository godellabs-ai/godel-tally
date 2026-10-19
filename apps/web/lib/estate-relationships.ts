import type { EstateRecord } from "./estate";
import { estateNeighborIndex } from "./estate-analysis";

// Follow reported relationships downstream; shared services never join different callers.
const journeyStage: Record<string, number> = { identity: 0, device: 1, workload: 2, agent: 3, workflow: 3, data_category: 3.5, mcp_config: 4, mcp_server: 5, endpoint: 6, data_source: 6 };
function forwardEdges(nodes: EstateRecord[], edges: EstateRecord[]) {
  const byId = new Map(nodes.map(record => [record.id, record]));
  return edges.filter(edge => {
    const source = byId.get(edge.detail.source ?? ""), target = byId.get(edge.detail.target ?? "");
    if (!source || !target || source.id === target.id) return false;
    // Models and providers remain inventory, rather than data destinations.
    if ([source, target].some(record => ["model", "provider"].includes(record.detail.kind))) return false;
    const from = journeyStage[source.detail.kind], to = journeyStage[target.detail.kind] ?? 9;
    // Unknown resource kinds are leaves. Recorded child-agent execution is the
    // only same-stage step; traversal still excludes every visited ancestor.
    return from !== undefined && (to > from || from === 3 && to === 3 && ["spawns", "calls", "contains"].includes(edge.detail.kind));
  });
}


export function estateForwardNeighbors(nodes: EstateRecord[], edges: EstateRecord[]) {
  return estateNeighborIndex(nodes, forwardEdges(nodes, edges), true);
}
