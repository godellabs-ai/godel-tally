import { type EstateRecord } from "./estate";

/** One connected entity with every recorded edge to it folded together. */
export interface EstateNeighbor {
  record: EstateRecord;
  relations: Array<{ label: string; outgoing: boolean }>;
  edges: EstateRecord[];
  confidence: string;
  lastSeen: number;
  sources: string[];
}
const confidenceRank: Record<string, number> = { confirmed: 0, source_reported: 1, unattributed: 2, historical: 3 };
const statusRank = (record: EstateRecord) => record.sanctioned === false ? 0 : record.sanctioned == null ? 1 : 2;

/**
 * Neighbours per entity. Several sources often report the same relationship (Defender, Gate runtime,
 * LiteLLM), so edges are grouped by the entity they reach. Riskiest first, then by name.
 */
export function estateNeighborIndex(nodes: EstateRecord[], edges: EstateRecord[], outgoingOnly = false) {
  const byId = new Map(nodes.map(n => [n.id, n]));
  const index = new Map<string, Map<string, EstateNeighbor>>();
  const add = (from: EstateRecord, to: EstateRecord, edge: EstateRecord, outgoing: boolean) => {
    const list = index.get(from.id) ?? new Map<string, EstateNeighbor>();
    index.set(from.id, list);
    const item = list.get(to.id) ?? { record: to, relations: [], edges: [], confidence: edge.detail.confidence, lastSeen: 0, sources: [] };
    list.set(to.id, item);
    item.edges.push(edge);
    if (!item.relations.some(r => r.label === edge.detail.kind && r.outgoing === outgoing)) item.relations.push({ label: edge.detail.kind, outgoing });
    if ((confidenceRank[edge.detail.confidence] ?? 9) < (confidenceRank[item.confidence] ?? 9)) item.confidence = edge.detail.confidence;
    item.lastSeen = Math.max(item.lastSeen, edge.last_seen);
    if (!item.sources.includes(edge.detail.connector_type)) item.sources.push(edge.detail.connector_type);
  };
  for (const edge of edges) {
    const source = byId.get(edge.detail.source ?? ""), target = byId.get(edge.detail.target ?? "");
    if (!source || !target || source.id === target.id) continue;
    add(source, target, edge, true);
    if (!outgoingOnly) add(target, source, edge, false);
  }
  return new Map([...index].map(([id, list]) => [id, [...list.values()].sort((a, b) => statusRank(a.record) - statusRank(b.record) || a.record.detail.name.localeCompare(b.record.detail.name))]));
}
/** "runs →", "← observed on", with "+1" when the same pair has more than one relationship. */
export function estateRelationText(neighbor: EstateNeighbor) {
  const [first, ...rest] = neighbor.relations;
  return `${first.outgoing ? `${first.label} →` : `← ${first.label}`}${rest.length ? ` +${rest.length}` : ""}`;
}
