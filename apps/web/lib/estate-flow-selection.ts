import type { EstateFlowPath } from "./estate-event-flow";
import { estateRecordIds, type EstateRecord } from "./estate";
import { authorizationStatusDisplayName, sourceDisplayName, verdictDisplayName } from "./estate-flow-labels";

export type FlowLens = "all" | "unsanctioned" | "review" | "exposure" | "protected";
export type FlowRisk = "all" | "unsanctioned" | "unprotected" | "flagged" | "offline" | "blocked" | "warned";
export interface FlowScope { lens: FlowLens; risk: FlowRisk }
export const defaultFlowScope: FlowScope = { lens: "all", risk: "all" };
export const flowLenses = [{ id: "all", label: "All activity" }, { id: "unsanctioned", label: "Unsanctioned AI" }, { id: "review", label: "Needs review" }, { id: "exposure", label: "Exposure paths" }, { id: "protected", label: "Protected" }] as const;
export const flowRisks = [{ id: "all", label: "All risks" }, { id: "unsanctioned", label: "Unsanctioned" }, { id: "unprotected", label: "Unprotected devices" }, { id: "flagged", label: "Flagged for review" }, { id: "offline", label: "Offline protection" }, { id: "blocked", label: "Blocked" }, { id: "warned", label: "Warned" }] as const;

export function flowPathValues(path: EstateFlowPath): Record<string, string> {
  return { User: path.user || "Unknown User", Authorization: authorizationStatusDisplayName(path.authorization_status),
    Agent: path.agent || "Unknown Agent", Taxonomy: path.domain, Source: path.source ? sourceDisplayName(path.source) : "None", Verdict: verdictDisplayName(path.verdict) };
}
export function flowPathRisks(path: EstateFlowPath): Set<Exclude<FlowRisk, "all">> {
  const risks = new Set<Exclude<FlowRisk, "all">>(path.risks ?? []);
  if (authorizationStatusDisplayName(path.authorization_status) === "Unsanctioned") risks.add("unsanctioned");
  const verdict = verdictDisplayName(path.verdict);
  if (verdict === "blocked" || verdict === "warned") risks.add(verdict);
  return risks;
}
export function scopeEventPaths(paths: EstateFlowPath[], scope: FlowScope) {
  return paths.filter(path => {
    if (scope.lens === "unsanctioned") return authorizationStatusDisplayName(path.authorization_status) === "Unsanctioned";
    if (scope.lens === "review") return authorizationStatusDisplayName(path.authorization_status) === "Review";
    if (scope.lens === "protected") return path.protected === true;
    if (scope.lens === "exposure") { const risks = flowPathRisks(path); return scope.risk === "all" ? risks.size > 0 : risks.has(scope.risk); }
    return true;
  });
}
/** OR within a column; AND across columns. Always match a complete path before collecting its assets. */
export function selectEventPaths(paths: EstateFlowPath[], nodeIds: string[]) {
  const dimensions = new Map<string, Set<string>>();
  for (const id of nodeIds) {
    const split = id.indexOf(":"), dimension = id.slice(0, split), values = dimensions.get(dimension) ?? new Set<string>();
    values.add(id.slice(split + 1)); dimensions.set(dimension, values);
  }
  return paths.filter(path => { const values = flowPathValues(path); return [...dimensions].every(([dimension, selected]) => selected.has(values[dimension])); });
}
export function inventoryForEventPaths(records: EstateRecord[], paths: EstateFlowPath[]) {
  const ids = new Set(paths.flatMap(path => path.recordIds ?? []));
  return records.filter(record => estateRecordIds(record).some(id => ids.has(id)));
}

export interface EstateOverviewSelection {
  active: boolean; nodeIds: string[]; paths: EstateFlowPath[]; records: EstateRecord[]; label: string;
}
