"use client";
import { useMemo, useState, type ReactNode } from "react";
import { RefreshCw, X } from "lucide-react";
import type { EstateRecord } from "../lib/estate";
import { connectorEventFlow, findingsEventFlow, type EstateEventFlow } from "../lib/estate-event-flow";
import { defaultFlowScope, flowLenses, flowRisks, inventoryForEventPaths, scopeEventPaths, selectEventPaths, type EstateOverviewSelection, type FlowScope } from "../lib/estate-flow-selection";
import { EstateEventFlowOverview } from "./estate-event-flow-overview";
import type { EventFlowDiagramProps } from "./estate-event-flow-diagram";
import { EstateRecordTable, type EstateReview } from "./estate-record-table";
import { useEstateInventory } from "./use-estate-inventory";
import type { EventAuthorizationStatus } from "../lib/event-stream";
import { SampleData } from "./sample-data";
import { useCurrentUser } from "../lib/current-user";
import { useGovernanceFindings } from "./use-governance-findings";
import { EventStream } from "./event-stream";

export interface EstateOverviewProps extends Pick<EventFlowDiagramProps, "formatAgent" | "logoForNode" | "sourceIcon" | "showRuntimeColumns" | "onAuthorizationNodeClick" | "onAuthorizationColumnClick"> {
  flow: EstateEventFlow; records: EstateRecord[]; loading?: boolean; error?: ReactNode;
  refresh?: () => void; loadMore?: () => void; onReview?: EstateReview;
  /** Hosts can keep the graph without rendering an inventory section. */
  showInventory?: boolean;
  inventoryContent?: (selection: EstateOverviewSelection) => ReactNode;
  selectionAction?: (ids: string[], paths: EstateEventFlow["paths"]) => ReactNode;
}

export function EstateOverview({ flow, records, loading, error, refresh, loadMore, onReview, showInventory = true, inventoryContent, selectionAction, showRuntimeColumns = false, ...presentation }: EstateOverviewProps) {
  const [scope, setScope] = useState<FlowScope>(defaultFlowScope), [nodeIds, setNodeIds] = useState<string[]>([]);
  const scopedPaths = useMemo(() => scopeEventPaths(flow.paths, scope), [flow.paths, scope]);
  const selectedPaths = useMemo(() => selectEventPaths(scopedPaths, nodeIds), [scopedPaths, nodeIds]);
  const active = scope.lens !== "all" || nodeIds.length > 0;
  const selectedRecords = useMemo(() => active ? inventoryForEventPaths(records, selectedPaths) : records, [active, records, selectedPaths]);
  const label = [scope.lens !== "all" ? flowLenses.find(lens => lens.id === scope.lens)?.label : null,
    scope.lens === "exposure" && scope.risk !== "all" ? flowRisks.find(risk => risk.id === scope.risk)?.label : null,
    ...nodeIds.map(id => { const split = id.indexOf(":"), value = id.slice(split + 1); return `${id.slice(0, split)} · ${id.startsWith("Agent:") ? presentation.formatAgent?.(value) ?? value : value}`; })].filter(Boolean).join(", ");
  const selection: EstateOverviewSelection = { active, nodeIds, paths: selectedPaths, records: selectedRecords, label };
  const filteredFlow = scopedPaths.length === flow.paths.length ? flow : { ...flow, paths: scopedPaths, verdicts: [] };
  const protectionAvailable = flow.paths.some(path => path.protected || path.risks?.some(risk => risk === "unprotected" || risk === "offline"));
  return <div className="min-w-0 space-y-6" aria-label="AI overview">
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Overview filters">
        {flowLenses.filter(lens => lens.id !== "protected" || protectionAvailable).map(lens => <button key={lens.id} type="button" aria-pressed={scope.lens === lens.id} onClick={() => setScope(old => ({ ...old, lens: lens.id, risk: "all" }))}
          className={`rounded-lg border px-3 py-2 text-xs font-medium transition-colors ${scope.lens === lens.id ? "border-primary bg-primary text-primary-foreground" : "border-border bg-card text-muted-foreground hover:text-foreground"}`}>{lens.label}</button>)}
        {refresh ? <button type="button" aria-label="Refresh overview" disabled={loading} onClick={refresh} className="rounded-lg border border-border p-2 text-muted-foreground hover:text-foreground"><RefreshCw className={`size-4 ${loading ? "animate-spin" : ""}`}/></button> : null}
        {active ? <button className="flex items-center gap-1 px-2 py-1 text-xs text-primary" onClick={() => { setNodeIds([]); setScope(defaultFlowScope); }}><X className="size-3.5"/>Clear filters</button> : null}
        {loadMore ? <button className="text-xs text-primary" onClick={loadMore} disabled={loading}>{showInventory ? "Load more inventory" : "Load more"}</button> : null}
      </div>
      {scope.lens === "exposure" ? <div className="flex flex-wrap gap-2" role="group" aria-label="Exposure risk filters">{flowRisks.filter(risk => (!['unprotected', 'offline'].includes(risk.id) || protectionAvailable) && (showRuntimeColumns || !['blocked', 'warned'].includes(risk.id))).map(risk => <button type="button" key={risk.id} aria-pressed={scope.risk === risk.id} onClick={() => setScope(old => ({ ...old, risk: risk.id }))} className={`rounded-full border px-3 py-1 text-xs ${scope.risk === risk.id ? "border-primary/40 bg-primary/10 text-primary" : "border-border text-muted-foreground"}`}>{risk.label}</button>)}</div> : null}
      {error}
      <EstateEventFlowOverview {...presentation} flow={filteredFlow} showRuntimeColumns={showRuntimeColumns} lockedNodeIds={nodeIds} onLockedNodeIdsChange={setNodeIds} expandPaths={scope.lens === "exposure"}
        selectionAction={selectionAction ? ids => selectionAction(ids, scopedPaths) : undefined}/>
      <p role="status" className="min-h-5 text-center text-sm text-muted-foreground">{!scopedPaths.length ? loading ? "Loading overview…" : "No matching activity." : ""}</p>
    </div>
    {showInventory ? <section id="inventory" aria-label="Overview inventory" className="min-w-0 scroll-mt-20 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-base font-semibold">Inventory</h2>{active ? <span className="text-xs text-muted-foreground">{label}</span> : null}</div>
      {inventoryContent ? inventoryContent(selection) : <div className="overflow-hidden rounded-xl border border-border bg-card"><EstateRecordTable records={selectedRecords} loading={loading} onReview={onReview}/></div>}
    </section> : null}
  </div>;
}

export function ConnectorOverview({ initialStatus = "all", initialQuery = "" }: { initialStatus?: EventAuthorizationStatus; initialQuery?: string }) {
  const inventory = useEstateInventory();
  const findings = useGovernanceFindings();
  const user = useCurrentUser();
  const [status, setStatus] = useState<EventAuthorizationStatus>(initialStatus);
  const [eventRefresh, setEventRefresh] = useState(0);
  const refresh = () => { inventory.refresh(); void findings.refresh(); setEventRefresh(value => value + 1); };
  const records = useMemo(() => inventory.data?.records ?? [], [inventory.data]);
  const flow = useMemo(() => {
    const connectors = connectorEventFlow(records.filter(record => record.record_type === "node"), records.filter(record => record.record_type === "edge"));
    const observed = findings.data ? findingsEventFlow(findings.data) : null;
    return { ...connectors, paths: [...connectors.paths, ...(observed?.paths ?? [])] };
  }, [records, findings.data]);
  return <div className="min-w-0 space-y-6">
    {user?.role === "admin" && inventory.data && findings.data && !inventory.loading && !findings.loading && !inventory.error && !findings.error && records.length === 0 &&
      findings.data.unsanctioned.length + findings.data.authorization_queue.length + findings.data.sanctioned.length === 0 ?
      <SampleData empty onChanged={refresh} /> : null}
    <EstateOverview showInventory={false} flow={flow} records={records.filter(record => record.record_type === "node")} loading={inventory.loading || findings.loading}
      refresh={refresh} loadMore={inventory.loadMore}
      onAuthorizationColumnClick={() => setStatus("authorization_queue")}
      onAuthorizationNodeClick={value => setStatus(value === "Sanctioned" ? "sanctioned" : value === "Unsanctioned" ? "unsanctioned" : "authorization_queue")}
      error={<>{inventory.error ? <p role="alert" className="text-sm text-destructive">{inventory.error}</p> : null}{findings.error ? <p role="alert" className="text-sm text-destructive">{findings.error} <button type="button" className="underline" onClick={() => void findings.refresh()}>Retry</button></p> : null}</>}/>
    <section id="findings" aria-label="Overview findings" className="min-w-0 scroll-mt-20 space-y-3">
      <EventStream initialQuery={initialQuery} refreshToken={eventRefresh} status={status} onStatusChange={setStatus}/>
    </section>
  </div>;
}
