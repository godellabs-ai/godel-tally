"use client";

import { useMemo, useState } from "react";
import { X } from "lucide-react";
import { EventFlowDiagram, type EventFlowDiagramProps } from "./estate-event-flow-diagram";
import type { ReactNode } from "react";
import type { EstateEventFlow } from "../lib/estate-event-flow";

/** The original Overview graph, including its column styling and path-selection interactions. */
export function EstateEventFlowOverview({ flow, onAuthorizationNodeClick, selectionAction, showRuntimeColumns = true, lockedNodeIds: controlledIds, onLockedNodeIdsChange, expandPaths, ...presentation }: {
  flow: EstateEventFlow; onAuthorizationNodeClick?: (status: string) => void;
  selectionAction?: (ids: string[]) => ReactNode;
  lockedNodeIds?: string[]; onLockedNodeIdsChange?: (ids: string[]) => void; expandPaths?: boolean;
} & Pick<EventFlowDiagramProps, "formatAgent" | "logoForNode" | "sourceIcon" | "showRuntimeColumns" | "onAuthorizationColumnClick">) {
  const { formatAgent } = presentation;
  const [localIds, setLocalIds] = useState<string[]>([]);
  const lockedNodeIds = controlledIds ?? localIds;
  const setLockedNodeIds = onLockedNodeIdsChange ?? setLocalIds;
  const filters = useMemo(() => lockedNodeIds.map(nodeId => {
    const split = nodeId.indexOf(":");
    const dimension = nodeId.slice(0, split), value = nodeId.slice(split + 1);
    return { nodeId, label: `${dimension === "Taxonomy" ? "Classification" : dimension} · ${dimension === "Agent" ? formatAgent?.(value) ?? value : value}` };
  }), [lockedNodeIds, formatAgent]);
  return <section className="min-w-0 space-y-3" aria-label="Overview event flow">
    <div className="w-full overflow-x-auto rounded-xl border border-border" data-overview-canvas>
      <EventFlowDiagram {...presentation} expandPaths={expandPaths} showRuntimeColumns={showRuntimeColumns} paths={flow.paths} totalEvents={flow.events} verdictCounts={flow.verdicts}
        lockedNodeIds={lockedNodeIds} onLockedNodeIdsChange={setLockedNodeIds}
        onAuthorizationNodeClick={onAuthorizationNodeClick} className={`m-0 w-full ${showRuntimeColumns ? "min-w-[1080px]" : "min-w-[720px]"}`}/>
    </div>
    {lockedNodeIds.length ? <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-primary/25 bg-primary/5 px-4 py-3 dark:bg-primary/10">
      <div className="min-w-0 space-y-1.5">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Active filters ({filters.length}):</span>
          {filters.map(filter => <span key={filter.nodeId} className="inline-flex items-center gap-1 rounded-md border border-primary/30 bg-card px-2 py-0.5 text-xs font-medium text-foreground shadow-xs">
            {filter.label}<button type="button" onClick={() => setLockedNodeIds(lockedNodeIds.filter(id => id !== filter.nodeId))}
              className="ml-0.5 rounded-xs p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground" aria-label={`Remove filter ${filter.label}`}><X className="size-3"/></button>
          </span>)}
        </div>
      </div>
      <div className="flex items-center gap-2">
        <button type="button" onClick={() => setLockedNodeIds([])} className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-card px-3 text-xs font-bold text-muted-foreground shadow-xs hover:text-foreground"><X className="size-3.5"/>Clear all</button>
        {selectionAction?.(lockedNodeIds)}
      </div>
    </div> : null}
  </section>;
}
