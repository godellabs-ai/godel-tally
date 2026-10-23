"use client";

import React, { useMemo, useState, useRef, useEffect, useLayoutEffect } from "react";
import { Server, User, Bot, Database, ShieldCheck, ShieldAlert, ShieldX, FolderCheck, Clock3, Search, CircleHelp } from "lucide-react";
import { flowPathHasColumn, type EstateFlowPath as FlowPath, type EstateFlowCount as NamedCount } from "../lib/estate-event-flow";
import { cn } from "@/lib/utils";

import { authorizationStatusDisplayName, sourceDisplayName, verdictDisplayName, hasReportedDecision } from "../lib/estate-flow-labels";
export { authorizationStatusDisplayName, sourceDisplayName, verdictDisplayName } from "../lib/estate-flow-labels";

const identityLabel = (name: string) => name;
function nodeCount(node: DiagramNode) {
  return [node.events ? `${node.events} events` : "", node.findingIds.size ? `${node.findingIds.size} ${node.findingIds.size === 1 ? "finding" : "findings"}` : "", node.discoveries ? `${node.discoveries} ${node.discoveries === 1 ? "path" : "paths"}` : ""].filter(Boolean).join(" · ") || "0 events";
}
// Both embedding hosts expose the active theme on the document; no host provider dependency.
function useDiagramTheme() {
  const [theme, setTheme] = useState("light");
  useEffect(() => {
    const update = () => setTheme(document.documentElement.classList.contains("dark") ? "dark" : "light");
    update();
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => observer.disconnect();
  }, []);
  return theme;
}

// Node names that represent an "absence" (no MCP source / no content classification). They always
// sort to the bottom of their column regardless of count.
const BOTTOM_NODE_NAMES = new Set(["None", "Unclassified", "Unknown", "Unknown User", "Unknown Agent"]);

const TAXONOMY_DIAGRAM_COLOR = "var(--diagram-taxonomy)";


export interface EventFlowDiagramProps {
  /** Aggregated User→AI authorization→Agent→Taxonomy→Source→Verdict paths. */
  paths: FlowPath[];
  /** Total events matching the flow window (informational; node values carry the path counts). */
  totalEvents?: number;
  /** Exact verdict event counts, calculated before paths fan out across business domains. */
  verdictCounts?: NamedCount[];
  /** Gate runtime evidence supplies classification and decision columns; standalone Tally omits them. */
  showRuntimeColumns?: boolean;
  lockedNodeId?: string | null;
  onLockedNodeIdChange?: (id: string | null) => void;
  lockedNodeIds?: string[];
  onLockedNodeIdsChange?: (ids: string[]) => void;
  /** Authorization nodes navigate to the matching inventory tab while also narrowing inventory. */
  onAuthorizationNodeClick?: (status: string) => void;
  onAuthorizationColumnClick?: () => void;
  expandPaths?: boolean;
  className?: string;
  formatAgent?: (name: string) => string;
  logoForNode?: (category: string, name: string) => string | null;
  sourceIcon?: (name: string) => React.ComponentType<{ className?: string; strokeWidth?: number }> | undefined;
}

export interface DiagramNode {
  id: string;
  name: string;
  category: string;
  value: number;
  events: number;
  discoveries: number;
  findingIds: Set<string>;
  /** Indices into `paths` that traverse this node (drives hover/lock reachability). */
  pathIds: Set<number>;
}

const COLUMN_HEADERS = [
  { id: "User", label: "Users", icon: User },
  { id: "Authorization", label: "AI Authorization", icon: ShieldCheck },
  { id: "Agent", label: "Agents", icon: Bot },
  { id: "Taxonomy", label: "Content Classification", icon: FolderCheck },
  { id: "Source", label: "MCP Server / Data Source", icon: Database },
  { id: "Verdict", label: "Decision", icon: ShieldCheck },
];

const getCategoryStyles = (category?: string, name?: string, theme?: string) => {
  const isDark = theme === "dark";
  switch (category) {
    case "Authorization": {
      const status = (name || "").toLowerCase();
      if (status.includes("unsanctioned")) {
        return {
          icon: ShieldX,
          color: "text-diagram-blocked",
          bg: "bg-diagram-blocked",
          border: "border-diagram-blocked",
          line: isDark ? "#f43f5e" : "#d93b4c"
        };
      }
      if (
        status.includes("review") ||
        status.includes("pending") ||
        status.includes("queue") ||
        status.includes("warn")
      ) {
        return {
          icon: Clock3,
          color: "text-diagram-warn",
          bg: "bg-diagram-warn",
          border: "border-diagram-warn",
          line: isDark ? "#fbbf24" : "#c87513"
        };
      }
      return {
        icon: ShieldCheck,
        color: "text-diagram-allowed",
        bg: "bg-diagram-allowed",
        border: "border-diagram-allowed",
        line: isDark ? "#34d399" : "#15946a"
      };
    }
    case "User":
      return {
        icon: User,
        color: "text-diagram-user",
        bg: "bg-diagram-user",
        border: "border-diagram-user",
        line: isDark ? "#818cf8" : "#7057d9"
      };
    case "Agent":
      return {
        icon: Bot,
        color: "text-diagram-agent",
        bg: "bg-diagram-agent",
        border: "border-diagram-agent",
        line: isDark ? "#2dd4bf" : "#0c9b8e"
      };
    case "Source":
      return {
        icon: Database,
        color: "text-diagram-source",
        bg: "bg-diagram-source",
        border: "border-diagram-source",
        line: isDark ? "#38bdf8" : "#1687c8"
      };
    case "Taxonomy":
      return {
        icon: FolderCheck,
        color: "text-diagram-taxonomy",
        bg: "bg-diagram-taxonomy",
        border: "border-diagram-taxonomy",
        line: isDark ? "#34d399" : "#10b981"
      };
    case "Verdict":
      const nameLower = (name || "").toLowerCase();
      if (nameLower === "unknown") return { icon: CircleHelp, color: "text-muted-foreground", bg: "bg-muted", border: "border-border", line: isDark ? "#94a3b8" : "#64748b" };
      if (nameLower.includes("block")) {
        return {
          icon: ShieldX,
          color: "text-diagram-blocked",
          bg: "bg-diagram-blocked",
          border: "border-diagram-blocked",
          line: isDark ? "#f43f5e" : "#d93b4c"
        };
      }
      if (nameLower.includes("warn")) {
        return {
          icon: ShieldAlert,
          color: "text-diagram-warn",
          bg: "bg-diagram-warn",
          border: "border-diagram-warn",
          line: isDark ? "#fbbf24" : "#c87513"
        };
      }
      return {
        icon: ShieldCheck,
        color: "text-diagram-allowed",
        bg: "bg-diagram-allowed",
        border: "border-diagram-allowed",
        line: isDark ? "#34d399" : "#15946a"
      };
    default:
      return {
        icon: Server,
        color: isDark ? "text-slate-400" : "text-slate-800",
        bg: isDark ? "bg-slate-950/40" : "bg-slate-200",
        border: isDark ? "border-slate-500/50" : "border-slate-400",
        line: isDark ? "#94a3b8" : "#64748b"
      };
  }
};

const PADDING = { top: 100, right: 80, bottom: 40, left: 80 };

export function EventFlowDiagram({
  paths,
  verdictCounts,
  showRuntimeColumns = true,
  lockedNodeId,
  onLockedNodeIdChange,
  lockedNodeIds,
  onLockedNodeIdsChange,
  onAuthorizationNodeClick,
  onAuthorizationColumnClick,
  className,
  expandPaths = false,
  formatAgent = identityLabel,
  logoForNode,
  sourceIcon,
}: EventFlowDiagramProps) {
  const resolvedTheme = useDiagramTheme();
  const columnHeaders = useMemo(() => COLUMN_HEADERS.filter(column => showRuntimeColumns || !["Taxonomy", "Verdict"].includes(column.id)), [showRuntimeColumns]);
  const columnGaps = columnHeaders.length - 1;
  const hasPaths = paths.length > 0;
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dim, setDim] = useState({ width: 1000, height: 650 });
  const [scrollOffsets, setScrollOffsets] = useState<number[]>([0, 0, 0, 0, 0, 0]);
  const scrollRefs = useRef<(HTMLDivElement | null)[]>([]);
  const [visibleCounts, setVisibleCounts] = useState<number[]>([20, 20, 20, 20, 20, 20]);
  const [colSearches, setColSearches] = useState<string[]>(["", "", "", "", "", ""]);
  const previousSearches = useRef(colSearches);
  useLayoutEffect(() => {
    colSearches.forEach((query, index) => {
      if (query !== previousSearches.current[index]) scrollRefs.current[index]?.scrollTo({ top: 0, behavior: "instant" });
    });
    previousSearches.current = colSearches;
  }, [colSearches]);

  const effectiveLockedIds = useMemo(() => {
    if (lockedNodeIds !== undefined) return lockedNodeIds;
    if (lockedNodeId) return [lockedNodeId];
    return [];
  }, [lockedNodeIds, lockedNodeId]);

  const effectiveLockedSet = useMemo(
    () => new Set(effectiveLockedIds),
    [effectiveLockedIds]
  );
  const hasLocked = effectiveLockedSet.size > 0;

  const handleToggleNode = (nodeId: string) => {
    if (onLockedNodeIdsChange) {
      const next = effectiveLockedSet.has(nodeId)
        ? effectiveLockedIds.filter((id) => id !== nodeId)
        : [...effectiveLockedIds, nodeId];
      onLockedNodeIdsChange(next);
    } else if (onLockedNodeIdChange) {
      onLockedNodeIdChange(lockedNodeId === nodeId ? null : nodeId);
    }
  };

  const handleNodeClick = (node: DiagramNode) => {
    if (node.category === "Authorization" && onAuthorizationNodeClick) {
      onAuthorizationNodeClick(node.name);
      if (onLockedNodeIdsChange) {
        onLockedNodeIdsChange([...effectiveLockedIds.filter(id => !id.startsWith("Authorization:")), node.id]);
        return;
      }
    }
    handleToggleNode(node.id);
  };

  const handleClear = () => {
    if (onLockedNodeIdsChange) {
      onLockedNodeIdsChange([]);
    }
    if (onLockedNodeIdChange) {
      onLockedNodeIdChange(null);
    }
  };

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver(entries => {
      if (entries[0]) {
        setDim({
          width: entries[0].contentRect.width,
          height: entries[0].contentRect.height
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, [hasPaths]);

  const data = useMemo(() => {
    const flowPaths = paths || [];
    if (flowPaths.length === 0) return { columns: [], links: [], maxLinkValue: 1 };

    const colNodes: Map<string, DiagramNode>[] = columnHeaders.map(() => new Map());

    const linksMap = new Map<string, { sourceId: string, targetId: string, value: number, pathIds: Set<number> }>();

    const cats = columnHeaders.map(column => column.id);

    // The server already fanned events out into one aggregated path per business domain; each path
    // contributes its count to one node per column. The path's array index plays the role the event
    // id used to: nodes/links sharing a path index are "related" for hover/lock highlighting.
    flowPaths.forEach((p, pathId) => {
      const values: Record<string, string> = {
        User: p.user || "Unknown User",
        Authorization: authorizationStatusDisplayName(p.authorization_status),
        Agent: p.agent || "Unknown Agent",
        Taxonomy: p.domain,
        Source: p.source ? sourceDisplayName(p.source) : "None",
        Verdict: verdictDisplayName(p.verdict),
      };
      const ids: string[] = [];
      cats.forEach((category, i) => {
        // Every path includes its AI application/runtime (or an explicitly unknown agent).
        // Findings do not establish content classifications or MCP/data-source connections.
        if (!flowPathHasColumn(p, category)) return;
        const value = values[category];
        const id = `${category}:${value}`;
        ids.push(id);
        if (!colNodes[i].has(id)) {
          let name = value;
          if (category === "Agent") {
            name = formatAgent(name);
          }
          colNodes[i].set(id, { id, name, category, value: 0, events: 0, discoveries: 0, findingIds: new Set(), pathIds: new Set() });
        }
        const node = colNodes[i].get(id)!;
        if (p.evidence === "finding" && p.findingId) node.findingIds.add(p.findingId);
        else if (p.evidence === "connector") node.discoveries += p.count;
        else node.events += p.count;
        node.value = node.events + node.discoveries + node.findingIds.size;
        node.pathIds.add(pathId);
      });

      for (let i = 0; i < ids.length - 1; i++) {
        const linkId = `${ids[i]}->${ids[i + 1]}`;
        if (!linksMap.has(linkId)) {
          linksMap.set(linkId, { sourceId: ids[i], targetId: ids[i + 1], value: 0, pathIds: new Set() });
        }
        const link = linksMap.get(linkId)!;
        link.value += p.count;
        link.pathIds.add(pathId);
      }
    });

    // A path is emitted once per business domain, so summing path counts inflates the final
    // Decision nodes for multi-domain events. Replace only that column with the server's exact
    // pre-fan-out verdict totals; pathIds remain attached for highlighting and filtering.
    const exactVerdicts = new Map<string, number>();
    for (const verdict of verdictCounts ?? []) {
      if (!hasReportedDecision(verdict.key)) continue;
      const name = verdictDisplayName(verdict.key);
      exactVerdicts.set(name, (exactVerdicts.get(name) ?? 0) + verdict.count);
    }
    const verdictNodes = colNodes[cats.indexOf("Verdict")];
    for (const [name, value] of exactVerdicts) {
      if (!verdictNodes) continue;
      const id = `Verdict:${name}`;
      const existing = verdictNodes.get(id);
      if (existing) {
        existing.events = value;
        existing.value = value + existing.discoveries;
      } else {
        verdictNodes.set(id, {
          id,
          name,
          category: "Verdict",
          value, events: value, discoveries: 0, findingIds: new Set(),
          pathIds: new Set(),
        });
      }
    }

    const columns = colNodes.map(m =>
      Array.from(m.values()).sort((a, b) => {
        const aBottom = BOTTOM_NODE_NAMES.has(a.name);
        const bBottom = BOTTOM_NODE_NAMES.has(b.name);
        if (aBottom !== bBottom) return aBottom ? 1 : -1;
        return b.value - a.value;
      })
    );
    const links = Array.from(linksMap.values());
    const maxLinkValue = Math.max(1, ...links.map(l => l.value));

    return { columns, links, maxLinkValue };
  }, [paths, verdictCounts, formatAgent, columnHeaders]);

  const nodesById = useMemo(() => {
    const map = new Map<string, DiagramNode>();
    for (const col of data.columns) {
      if (!col) continue;
      for (const node of col) {
        if (node?.id) map.set(node.id, node);
      }
    }
    return map;
  }, [data.columns]);

  const activePathIds = useMemo(() => {
    if (hasLocked) {
      const byCategory = new Map<string, Set<number>>();
      for (const id of effectiveLockedIds) {
        const node = nodesById.get(id);
        const category = id.slice(0, id.indexOf(":"));
        const set = byCategory.get(category) ?? new Set<number>();
        for (const pid of node?.pathIds ?? []) set.add(pid);
        byCategory.set(category, set);
      }
      if (byCategory.size === 0) return null;
      let intersection: Set<number> | null = null;
      for (const catPaths of byCategory.values()) {
        if (intersection === null) {
          intersection = new Set(catPaths);
        } else {
          const next = new Set<number>();
          for (const pid of intersection) {
            if (catPaths.has(pid)) next.add(pid);
          }
          intersection = next;
        }
      }
      return intersection;
    }
    if (hoveredNodeId) {
      const node = nodesById.get(hoveredNodeId);
      return node?.pathIds ? new Set(node.pathIds) : null;
    }
    return null;
  }, [hasLocked, effectiveLockedIds, hoveredNodeId, nodesById]);

  const sortedColumns = useMemo(() => {
    return data.columns.map((col, colIdx) => {
      if (!col) return [];
      // 1. Sort matching search nodes to the top
      let processedCol = col;
      const searchVal = colSearches[colIdx]?.trim().toLowerCase();
      if (searchVal) {
        const matched = col.filter(n => n && n.name && n.name.toLowerCase().includes(searchVal));
        const unmatched = col.filter(n => !n || !n.name || !n.name.toLowerCase().includes(searchVal));
        processedCol = [...matched, ...unmatched];
      }

      // 2. Promote related nodes if activePathIds is active
      const isFiltering = hasLocked || Boolean(hoveredNodeId);
      if (!isFiltering || !activePathIds) return processedCol;

      const isNodeRelated = (node: DiagramNode) => {
        if (!node) return false;
        if (effectiveLockedSet.has(node.id) || (hoveredNodeId && node.id === hoveredNodeId)) return true;
        if (!node.pathIds) return false;
        return Array.from(node.pathIds as Set<number>).some(id => activePathIds.has(id));
      };

      const limit = 6;

      // Separate hidden related nodes into normal and bottom
      const hiddenRelatedNormal: DiagramNode[] = [];
      const hiddenRelatedBottom: DiagramNode[] = [];
      
      for (let i = limit; i < processedCol.length; i++) {
        const node = processedCol[i];
        if (node && isNodeRelated(node)) {
          // If hovering, do NOT promote the hovered node itself to avoid jumping
          const isHoverOnly = !hasLocked && Boolean(hoveredNodeId);
          if (isHoverOnly && node.id === hoveredNodeId) continue;
          
          if (node.name && BOTTOM_NODE_NAMES.has(node.name)) {
            hiddenRelatedBottom.push(node);
          } else {
            hiddenRelatedNormal.push(node);
          }
        }
      }
      
      const nodesToSwapIn = [...hiddenRelatedBottom, ...hiddenRelatedNormal];
      
      if (nodesToSwapIn.length === 0) {
        return processedCol;
      }
      
      // Find available slots in the visible area to swap into
      const availableSlots: number[] = [];
      const slotsToCheck = Math.min(limit, processedCol.length);
      const newCol = [...processedCol];
      for (let i = 0; i < slotsToCheck; i++) {
        const node = newCol[i];
        if (!node) continue;
        if (effectiveLockedSet.has(node.id) || (hoveredNodeId && node.id === hoveredNodeId)) continue; // Don't move locked or hovered node!
        if (isNodeRelated(node)) continue; // Don't swap out already related nodes
        if (node.name && BOTTOM_NODE_NAMES.has(node.name)) continue; // Leave bottom nodes at bottom if already visible
        availableSlots.push(i);
      }
      
      // Swap Bottom nodes in first so they grab the slots with the highest index (closest to bottom)
      for (const hNode of nodesToSwapIn) {
        if (!hNode || !hNode.id) continue;
        if (availableSlots.length === 0) break;
        const slotIdx = availableSlots.pop()!; // Take highest available index
        const hIndex = newCol.findIndex(n => n && n.id === hNode.id);
        
        if (hIndex === -1) continue;
        
        // Swap perfectly
        const temp = newCol[slotIdx];
        if (!temp) continue;
        newCol[slotIdx] = newCol[hIndex];
        newCol[hIndex] = temp;
      }

      return newCol;
    });
  }, [data.columns, hasLocked, effectiveLockedSet, hoveredNodeId, activePathIds, colSearches]);

  const slicedColumns = useMemo(() => {
    return sortedColumns.map((col, colIdx) => {
      const limit = expandPaths ? Number.MAX_SAFE_INTEGER : visibleCounts[colIdx] || 20;
      return col.slice(0, limit);
    });
  }, [sortedColumns, visibleCounts, expandPaths]);

  // Reset scrollTop of all containers when locked nodes change so top-sorted nodes are immediately visible
  useEffect(() => {
    scrollRefs.current.forEach(ref => {
      if (ref) ref.scrollTop = 0;
    });
    const timer = setTimeout(() => {
      setScrollOffsets([0, 0, 0, 0, 0, 0]);
    }, 0);
    return () => clearTimeout(timer);
  }, [effectiveLockedIds]);

  const drawWidth = Math.max(100, dim.width - PADDING.left - (showRuntimeColumns ? PADDING.right : 120));

  const nodePositions = useMemo(() => {
    const pos = new Map<string, { cx: number, cy: number, node: DiagramNode }>();

    sortedColumns.forEach((col, colIdx) => {
      if (!col) return;
      const slicedColLength = slicedColumns[colIdx]?.length || 0;
      const cx = PADDING.left + (colIdx / columnGaps) * drawWidth;
      const nodeGap = 80;

      const colLimit = 6;
      const colHeight = 480;
      const totalColHeight = Math.max(0, slicedColLength - 1) * nodeGap;
      const boxHeight = totalColHeight + 72;
      const startYLocal = slicedColLength > colLimit ? 4 : (colHeight - boxHeight) / 2;

      col.forEach((node, rowIdx) => {
        if (node && node.id) {
          const offset = node.category === "Verdict" ? 24 : 20;
          const cy = PADDING.top + startYLocal + rowIdx * nodeGap + offset - scrollOffsets[colIdx];
          pos.set(node.id, { cx, cy, node });
        }
      });
    });

    return pos;
  }, [sortedColumns, scrollOffsets, drawWidth, slicedColumns, columnGaps]);

  if (data.columns.length === 0) {
    return (
      <div className="flex h-[650px] items-center justify-center text-sm text-muted-foreground bg-transparent">
        No data available for diagram.
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative h-[650px] w-[calc(100%+48px)] -mx-6 -mt-7 mb-6 bg-card overflow-hidden select-none shadow-xs",
        className
      )}
      onClick={handleClear}
      onMouseLeave={() => setHoveredNodeId(null)}
      style={{ backgroundImage: "radial-gradient(circle, color-mix(in srgb, var(--muted-foreground) 24%, transparent) 1px, transparent 1px)", backgroundSize: "20px 20px" }}
    >




      <style>{`
        :root {
          --diagram-user: #7057d9;
          --diagram-authorization: #15946a;
          --diagram-agent: #0c9b8e;
          --diagram-source: #1687c8;
          --diagram-allowed: #15946a;
          --diagram-warn: #c87513;
          --diagram-blocked: #d93b4c;
          --diagram-taxonomy: #10b981;

          --bg-diagram-user: rgba(112, 87, 217, 0.08);
          --border-diagram-user: rgba(112, 87, 217, 0.25);
          --bg-diagram-authorization: rgba(21, 148, 106, 0.08);
          --border-diagram-authorization: rgba(21, 148, 106, 0.25);
          --bg-diagram-agent: rgba(12, 155, 142, 0.08);
          --border-diagram-agent: rgba(12, 155, 142, 0.25);
          --bg-diagram-source: rgba(22, 135, 200, 0.08);
          --border-diagram-source: rgba(22, 135, 200, 0.25);
          --bg-diagram-taxonomy: rgba(16, 185, 129, 0.08);
          --border-diagram-taxonomy: rgba(16, 185, 129, 0.25);
          --bg-diagram-allowed: rgba(21, 148, 106, 0.08);
          --border-diagram-allowed: rgba(21, 148, 106, 0.25);
          --bg-diagram-warn: rgba(200, 117, 19, 0.08);
          --border-diagram-warn: rgba(200, 117, 19, 0.25);
          --bg-diagram-blocked: rgba(217, 59, 76, 0.08);
          --border-diagram-blocked: rgba(217, 59, 76, 0.25);
        }
        .dark {
          --diagram-user: #818cf8;
          --diagram-authorization: #34d399;
          --diagram-agent: #2dd4bf;
          --diagram-source: #38bdf8;
          --diagram-allowed: #34d399;
          --diagram-warn: #fbbf24;
          --diagram-blocked: #f43f5e;
          --diagram-taxonomy: #34d399;

          --bg-diagram-user: rgba(129, 140, 248, 0.12);
          --border-diagram-user: rgba(129, 140, 248, 0.25);
          --bg-diagram-authorization: rgba(52, 211, 153, 0.12);
          --border-diagram-authorization: rgba(52, 211, 153, 0.25);
          --bg-diagram-agent: rgba(45, 212, 191, 0.12);
          --border-diagram-agent: rgba(45, 212, 191, 0.25);
          --bg-diagram-source: rgba(56, 189, 248, 0.12);
          --border-diagram-source: rgba(56, 189, 248, 0.25);
          --bg-diagram-taxonomy: rgba(52, 211, 153, 0.12);
          --border-diagram-taxonomy: rgba(52, 211, 153, 0.25);
          --bg-diagram-allowed: rgba(52, 211, 153, 0.12);
          --border-diagram-allowed: rgba(52, 211, 153, 0.25);
          --bg-diagram-warn: rgba(251, 191, 36, 0.12);
          --border-diagram-warn: rgba(251, 191, 36, 0.25);
          --bg-diagram-blocked: rgba(244, 63, 94, 0.12);
          --border-diagram-blocked: rgba(244, 63, 94, 0.25);
        }
        
        .text-diagram-user { color: var(--diagram-user); }
        .bg-diagram-user { background-color: var(--bg-diagram-user); }
        .border-diagram-user { border-color: var(--border-diagram-user); }

        .text-diagram-authorization { color: var(--diagram-authorization); }
        .bg-diagram-authorization { background-color: var(--bg-diagram-authorization); }
        .border-diagram-authorization { border-color: var(--border-diagram-authorization); }

        .text-diagram-agent { color: var(--diagram-agent); }
        .bg-diagram-agent { background-color: var(--bg-diagram-agent); }
        .border-diagram-agent { border-color: var(--border-diagram-agent); }

        .text-diagram-source { color: var(--diagram-source); }
        .bg-diagram-source { background-color: var(--bg-diagram-source); }
        .border-diagram-source { border-color: var(--border-diagram-source); }

        .text-diagram-taxonomy { color: var(--diagram-taxonomy); }
        .bg-diagram-taxonomy { background-color: var(--bg-diagram-taxonomy); }
        .border-diagram-taxonomy { border-color: var(--border-diagram-taxonomy); }

        .text-diagram-allowed { color: var(--diagram-allowed); }
        .bg-diagram-allowed { background-color: var(--bg-diagram-allowed); }
        .border-diagram-allowed { border-color: var(--border-diagram-allowed); }

        .text-diagram-warn { color: var(--diagram-warn); }
        .bg-diagram-warn { background-color: var(--bg-diagram-warn); }
        .border-diagram-warn { border-color: var(--border-diagram-warn); }

        .text-diagram-blocked { color: var(--diagram-blocked); }
        .bg-diagram-blocked { background-color: var(--bg-diagram-blocked); }
        .border-diagram-blocked { border-color: var(--border-diagram-blocked); }

        /* Flow nodes formatting matching HTML reference exactly */
        .flow-node {
          display: flex;
          transition: opacity 0.18s ease, transform 0.18s ease, filter 0.18s ease;
        }
        .flow-node.non-decision {
          flex-direction: column;
          gap: 6px;
          align-items: center;
        }
        .flow-node.decision {
          flex-direction: row;
          align-items: center;
          width: 130px;
          padding: 8px 12px;
          border-radius: 28px;
          border: 1px solid var(--border);
          background: var(--card);
          box-shadow: 0 12px 30px rgba(23, 32, 42, 0.04);
          gap: 12px;
        }
        .dark .flow-node.decision {
          background: rgba(255, 255, 255, 0.02);
          border-color: rgba(255, 255, 255, 0.08);
          box-shadow: none;
        }

        .flow-node.decision.unknown { color: var(--muted-foreground); background: var(--muted); border-color: var(--border); }
        .edge.active-base.unknown, .edge.active-glow.unknown { stroke: var(--muted-foreground); }
        .flow-node.user { color: var(--diagram-user); }
        .flow-node.authorization { color: var(--diagram-authorization); }
        .flow-node.authorization.sanctioned,
        .flow-node.authorization.allowed {
          color: var(--diagram-allowed);
        }
        .flow-node.authorization.review,
        .flow-node.authorization.warned,
        .flow-node.authorization.sanction-pending,
        .flow-node.authorization.pending {
          color: var(--diagram-warn);
        }
        .flow-node.authorization.unsanctioned,
        .flow-node.authorization.blocked {
          color: var(--diagram-blocked);
        }
        .flow-node.agent { color: var(--diagram-agent); }
        .flow-node.taxonomy { color: var(--diagram-taxonomy); }
        .flow-node.source { color: var(--diagram-source); }

        .flow-node.decision.allowed,
        .flow-node.decision.pass,
        .flow-node.decision[data-title*="allowed"],
        .flow-node.decision[data-title*="pass"] {
          background: rgba(21, 148, 106, 0.08);
          border-color: rgba(21, 148, 106, 0.35);
          color: var(--diagram-allowed);
        }
        .dark .flow-node.decision.allowed,
        .dark .flow-node.decision.pass,
        .dark .flow-node.decision[data-title*="allowed"],
        .dark .flow-node.decision[data-title*="pass"] {
          background: rgba(52, 211, 153, 0.12);
          border-color: rgba(52, 211, 153, 0.35);
          color: var(--diagram-allowed);
        }
        .flow-node.decision.allowed.active,
        .flow-node.decision.pass.active {
          background: #e9fbf4;
          border-color: #34d399;
          box-shadow: 0 4px 16px rgba(21, 148, 106, 0.2);
        }
        .dark .flow-node.decision.allowed.active,
        .dark .flow-node.decision.pass.active {
          background: rgba(16, 185, 129, 0.2);
          border-color: #34d399;
          box-shadow: 0 4px 16px rgba(52, 211, 153, 0.2);
        }

        .flow-node.decision.warned,
        .flow-node.decision.warn,
        .flow-node.decision[data-title*="warn"] {
          background: rgba(200, 117, 19, 0.08);
          border-color: rgba(200, 117, 19, 0.35);
          color: var(--diagram-warn);
        }
        .dark .flow-node.decision.warned,
        .dark .flow-node.decision.warn,
        .dark .flow-node.decision[data-title*="warn"] {
          background: rgba(251, 191, 36, 0.12);
          border-color: rgba(251, 191, 36, 0.35);
          color: var(--diagram-warn);
        }
        .flow-node.decision.warned.active,
        .flow-node.decision.warn.active {
          background: #fff4df;
          border-color: #fca73f;
          box-shadow: 0 4px 16px rgba(200, 117, 19, 0.2);
        }
        .dark .flow-node.decision.warned.active,
        .dark .flow-node.decision.warn.active {
          background: rgba(245, 158, 11, 0.2);
          border-color: #fbbf24;
          box-shadow: 0 4px 16px rgba(251, 191, 36, 0.2);
        }

        .flow-node.decision.blocked,
        .flow-node.decision.block,
        .flow-node.decision[data-title*="block"] {
          background: rgba(217, 59, 76, 0.08);
          border-color: rgba(217, 59, 76, 0.35);
          color: var(--diagram-blocked);
        }
        .dark .flow-node.decision.blocked,
        .dark .flow-node.decision.block,
        .dark .flow-node.decision[data-title*="block"] {
          background: rgba(244, 63, 94, 0.12);
          border-color: rgba(244, 63, 94, 0.35);
          color: var(--diagram-blocked);
        }
        .flow-node.decision.blocked.active,
        .flow-node.decision.block.active {
          background: #fff0f2;
          border-color: #ff6e7f;
          box-shadow: 0 4px 16px rgba(217, 59, 76, 0.2);
        }
        .dark .flow-node.decision.blocked.active,
        .dark .flow-node.decision.block.active {
          background: rgba(244, 63, 94, 0.2);
          border-color: #f43f5e;
          box-shadow: 0 4px 16px rgba(244, 63, 94, 0.2);
        }

        .flow-node.dim {
          opacity: 0.24;
          filter: saturate(0.25);
        }
        .flow-node.dim:hover {
          opacity: 0.7;
          filter: saturate(0.8);
          transform: translateY(-1px);
        }
        .flow-node.active {
          opacity: 1;
          filter: saturate(1);
        }
        .flow-node.active:hover {
          transform: translateY(-1px);
        }

        .flow-icon {
          display: grid;
          place-items: center;
          border: 2px solid currentColor;
          transition: all 0.18s ease;
          background: linear-gradient(180deg, color-mix(in srgb, currentColor 13%, var(--card)), var(--card));
          box-shadow: 0 9px 20px color-mix(in srgb, currentColor 10%, transparent);
        }
        .dark .flow-icon {
          background: linear-gradient(180deg, color-mix(in srgb, currentColor 20%, rgba(255,255,255,0.02)), rgba(255,255,255,0.02));
        }

        .flow-icon.has-logo {
          background: #ffffff !important;
          border-width: 2.5px !important;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.04) !important;
        }
        .dark .flow-icon.has-logo {
          background: #ffffff !important;
          border-width: 2.5px !important;
        }

        .flow-node.active .flow-icon {
          background: currentColor;
          box-shadow: 0 10px 24px color-mix(in srgb, currentColor 20%, transparent);
        }
        .flow-node.active .flow-icon svg {
          stroke: var(--card) !important;
        }
        .dark .flow-node.active .flow-icon svg {
          stroke: #0a0a0f !important;
        }

        .flow-node.dim .flow-icon {
          background: #f7f9fc;
          color: #b8c0cc;
          border-color: #d6dde7;
          box-shadow: none;
        }
        .dark .flow-node.dim .flow-icon {
          background: rgba(255, 255, 255, 0.01);
          color: rgba(255, 255, 255, 0.15);
          border-color: rgba(255, 255, 255, 0.05);
        }

        .flow-node:not(.decision) .flow-icon {
          width: 38px;
          height: 38px;
          border-radius: 12px;
        }
        .flow-node.user .flow-icon {
          border-radius: 50%;
        }
        .flow-node.decision .flow-icon {
          width: 32px;
          height: 32px;
          border-radius: 50%;
        }

        .flow-node.locked.non-decision .flow-icon {
          outline: 2px solid var(--primary);
          outline-offset: 2px;
        }
        .flow-node.locked.decision {
          outline: 2px solid var(--primary);
          outline-offset: 2px;
        }

        .flow-txt {
          display: flex;
          flex-direction: column;
          min-width: 0;
          flex: 1;
          text-align: left;
        }
        .flow-txt.center {
          align-items: center;
          text-align: center;
          width: 100%;
        }
        .flow-txt strong {
          display: block;
          font-size: 12px;
          line-height: 1.2;
          font-weight: 600;
          color: var(--foreground);
        }
        .flow-txt span {
          display: block;
          font-size: 10px;
          color: var(--muted-foreground);
          margin-top: 2px;
          font-weight: 500;
        }

        @keyframes dash-flow {
          from { stroke-dashoffset: 0; }
          to { stroke-dashoffset: -28; }
        }
        .animate-dash-flow {
          animation: dash-flow 0.8s linear infinite;
        }
        .no-scrollbar::-webkit-scrollbar {
          display: none;
        }
        .no-scrollbar {
          -ms-overflow-style: none;
          scrollbar-width: none;
        }


        /* Edge styles matching HTML reference exactly */
        .edge {
          fill: none;
          stroke: #c8d1de;
          stroke-linecap: round;
          opacity: 0.30;
          transition: all 0.18s ease;
        }
        .dark .edge {
          stroke: rgba(148, 163, 184, 0.18);
          opacity: 1;
        }
        .edge.dim {
          opacity: 0.045;
        }
        .dark .edge.dim {
          stroke: rgba(148, 163, 184, 0.06);
          opacity: 0.3;
        }
        .edge.active-base {
          opacity: 1;
          filter: drop-shadow(0 5px 8px rgba(22,135,200,0.12));
        }
        .dark .edge.active-base {
          opacity: 0.95;
          filter: none;
        }
        .edge.active-glow {
          opacity: 0.15;
          filter: blur(4px);
        }
        .dark .edge.active-glow {
          display: none;
        }
        .edge.flow-sheen {
          opacity: 0.55;
          stroke: #fff;
          stroke-dasharray: 26 220;
          animation: flowSheen 2.4s linear infinite;
        }
        .dark .edge.flow-sheen {
          opacity: 0.35;
          stroke: rgba(255, 255, 255, 0.7);
          filter: none;
        }
        @keyframes flowSheen {
          to { stroke-dashoffset: -246; }
        }

        .edge.active-base.user,
        .edge.active-glow.user {
          stroke: var(--diagram-user);
          --edge-glow-color: rgba(129, 140, 248, 0.45);
        }
        .edge.active-base.authorization,
        .edge.active-glow.authorization {
          stroke: var(--diagram-authorization);
          --edge-glow-color: rgba(52, 211, 153, 0.45);
        }
        .edge.active-base.sanctioned,
        .edge.active-glow.sanctioned {
          stroke: var(--diagram-allowed);
          --edge-glow-color: rgba(52, 211, 153, 0.45);
        }
        .edge.active-base.review,
        .edge.active-base.sanction-pending,
        .edge.active-glow.review,
        .edge.active-glow.sanction-pending {
          stroke: var(--diagram-warn);
          --edge-glow-color: rgba(251, 191, 36, 0.45);
        }
        .edge.active-base.unsanctioned,
        .edge.active-glow.unsanctioned {
          stroke: var(--diagram-blocked);
          --edge-glow-color: rgba(244, 63, 94, 0.45);
        }
        .edge.active-base.agent,
        .edge.active-glow.agent {
          stroke: var(--diagram-agent);
          --edge-glow-color: rgba(45, 212, 191, 0.45);
        }
        .edge.active-base.taxonomy,
        .edge.active-glow.taxonomy {
          stroke: var(--diagram-taxonomy);
          --edge-glow-color: rgba(52, 211, 153, 0.45);
        }
        .edge.active-base.source,
        .edge.active-glow.source {
          stroke: var(--diagram-source);
          --edge-glow-color: rgba(56, 189, 248, 0.45);
        }
        .edge.active-base.allowed,
        .edge.active-glow.allowed {
          stroke: var(--diagram-allowed);
          --edge-glow-color: rgba(52, 211, 153, 0.45);
        }
        .edge.active-base.warned,
        .edge.active-glow.warned {
          stroke: var(--diagram-warn);
          --edge-glow-color: rgba(251, 191, 36, 0.45);
        }
        .edge.active-base.blocked,
        .edge.active-glow.blocked {
          stroke: var(--diagram-blocked);
          --edge-glow-color: rgba(244, 63, 94, 0.45);
        }
      `}</style>

      {/* Modern vertical separator lines between sections */}
      {Array.from({ length: columnGaps }).map((_, i) => {
        const midX = PADDING.left + ((i + 0.5) / columnGaps) * drawWidth;
        return (
          <div
            key={i}
            className="absolute w-0 border-l border-dashed border-border/30 pointer-events-none z-0"
            style={{
              left: midX,
              top: 24,
              bottom: 24,
            }}
          />
        );
      })}

      {columnHeaders.map((col, i) => {
        const cx = PADDING.left + (i / columnGaps) * drawWidth;
        const Icon = col.icon;
        const style = getCategoryStyles(col.id, "", resolvedTheme);

        return (
          <div
            key={col.id}
            className="absolute flex flex-col items-center pointer-events-none z-20"
            style={{ left: cx - 100, top: 28, width: 200 }}
          >
            {col.id === "Authorization" && onAuthorizationColumnClick ? <button type="button" onClick={event => { event.stopPropagation(); onAuthorizationColumnClick(); }} className={`pointer-events-auto flex items-center gap-2 rounded px-2 py-1 text-xs font-bold tracking-wider hover:bg-primary/10 ${style.color}`}>
              <Icon className="size-4 shrink-0" strokeWidth={2.5}/>{col.label}
            </button> : <div className="flex items-center gap-2">
              <Icon className={`size-4 shrink-0 ${style.color}`} strokeWidth={2.5} />
              <span className={`text-xs font-bold tracking-wider ${style.color}`}>
                {col.label}
              </span>
            </div>}
          </div>
        );
      })}

      {columnHeaders.map((col, i) => {
        const cx = PADDING.left + (i / columnGaps) * drawWidth;
        const totalNodes = sortedColumns[i]?.length || 0;
        const showSearch = totalNodes > 10;

        if (!showSearch) return null;

        return (
          <div
            key={`search-${col.id}`}
            className="absolute z-30 pointer-events-auto flex items-center gap-1 border-b border-border transition-colors hover:border-muted-foreground/40 focus-within:border-primary"
            style={{ left: cx - 55, top: 58, width: 110, height: 22 }}
            onClick={event => event.stopPropagation()}
          >
            <Search className="size-3 text-muted-foreground/60 shrink-0" />
            <input
              type="text"
              placeholder="Search..."
                  aria-label={`Search ${col.label}`}
              value={colSearches[i]}
              onChange={(e) => {
                const newSearches = [...colSearches];
                newSearches[i] = e.target.value;
                setColSearches(newSearches);
                scrollRefs.current[i]?.scrollTo({ top: 0, behavior: "instant" });
                setScrollOffsets(offsets => offsets.map((offset, index) => index === i ? 0 : offset));
              }}
              className="w-full bg-transparent border-none rounded-none px-0.5 py-0.5 text-xs focus:outline-none focus:ring-0 text-foreground placeholder:text-muted-foreground/60"
            />
          </div>
        );
      })}

      <svg className="absolute inset-0 z-0 pointer-events-none" width={dim.width} height={dim.height}>
        {data.links.map(link => {
          if (!link) return null;
          const srcPos = nodePositions.get(link.sourceId);
          const tgtPos = nodePositions.get(link.targetId);
          if (!srcPos || !tgtPos) return null;

          const srcNode = srcPos.node;
          const tgtNode = tgtPos.node;
          if (!srcNode || !tgtNode) return null;

          const isRelated = !activePathIds ||
            Array.from(link.pathIds).some(id => activePathIds.has(id));

          const { cx: sx, cy: sy } = srcPos;
          const { cx: tx, cy: ty } = tgtPos;

          // Check if endpoints are within the visible scroll bounds of the columns
          const isSrcVisible = sy >= PADDING.top && sy <= PADDING.top + 480;
          const isTgtVisible = ty >= PADDING.top && ty <= PADDING.top + 480;
          if (!isSrcVisible || !isTgtVisible) return null;

          const linkKey = `${link.sourceId}-${link.targetId}`;

          const actualSx = sx + 20;
          const actualTx = tgtNode.category === "Verdict" ? tx - 65 : tx - 20;

          const controlDist = (actualTx - actualSx) * 0.5;
          const pathD = `M${actualSx},${sy} C${actualSx + controlDist},${sy} ${actualTx - controlDist},${ty} ${actualTx},${ty}`;

          // Determine the edge tone (class name)
          let tone = "";
          if (tgtNode.category === "Verdict") {
            tone = tgtNode.name; // allowed, warned, blocked
          } else if (srcNode.category === "Authorization") {
            const authStatus = srcNode.name.toLowerCase();
            if (authStatus.includes("unsanctioned")) {
              tone = "blocked";
            } else if (
              authStatus.includes("review") ||
              authStatus.includes("pending") ||
              authStatus.includes("queue") ||
              authStatus.includes("warn")
            ) {
              tone = "warned";
            } else {
              tone = "allowed";
            }
          } else {
            tone = srcNode.category.toLowerCase(); // user, agent, taxonomy, source
          }

          const computedWidth = Math.min(8, Math.max(2, (link.value / data.maxLinkValue) * 8));

          if (!activePathIds) {
            // No node is selected - show all edges as default
            return (
              <path
                key={linkKey}
                className="edge"
                data-flow-source={link.sourceId}
                data-flow-target={link.targetId}
                strokeWidth={computedWidth}
                d={pathD}
              />
            );
          }

          if (!isRelated) {
            // Node selected, but this edge is unrelated - show as dimmed
            return (
              <path
                key={linkKey}
                className="edge dim"
                data-flow-source={link.sourceId}
                data-flow-target={link.targetId}
                strokeWidth={computedWidth}
                d={pathD}
              />
            );
          }

          // Node selected and this edge is active/related
          return (
            <g key={linkKey} data-flow-source={link.sourceId} data-flow-target={link.targetId}>
              {/* Highlight drop shadow glow */}
              <path
                className={`edge active-glow ${tone}`}
                strokeWidth={computedWidth + 5}
                d={pathD}
              />
              {/* Active Base edge */}
              <path
                className={`edge active-base ${tone}`}
                strokeWidth={computedWidth}
                d={pathD}
              />
              {/* Moving sheen */}
              <path
                className="edge flow-sheen"
                strokeWidth={Math.max(1.5, computedWidth * 0.6)}
                d={pathD}
              />
            </g>
          );
        })}
      </svg>

      {slicedColumns.map((col, colIdx) => {
        const cx = PADDING.left + (colIdx / columnGaps) * drawWidth;
        const isDecision = columnHeaders[colIdx].id === "Verdict";
        const leftPos = cx - 65;

        const colLimit = 6;
        const colHeight = 480;
        const totalNodesCount = col.length;

        const totalColHeight = Math.max(0, totalNodesCount - 1) * 80;
        const boxHeight = totalColHeight + 72;
        const startYLocal = totalNodesCount > colLimit ? 4 : (colHeight - boxHeight) / 2;
        const innerHeight = totalNodesCount > colLimit ? totalNodesCount * 80 : colHeight;

        return (
          <div key={colIdx}>
            <div
              ref={el => { scrollRefs.current[colIdx] = el; }}
              role="group"
              aria-label={`${columnHeaders[colIdx].label} nodes`}
              tabIndex={totalNodesCount > colLimit ? 0 : undefined}
              className={`absolute no-scrollbar ${totalNodesCount > colLimit ? "overflow-y-auto" : "overflow-y-hidden"}`}
              style={{
                left: leftPos,
                top: PADDING.top,
                width: 130,
                height: colHeight,
                // Sorting search matches must not anchor the viewport to the old first node.
                overflowAnchor: "none",
              }}
              onScroll={(e) => {
                const target = e.target as HTMLDivElement;
                const scrollTop = target.scrollTop;
                const scrollHeight = target.scrollHeight;
                const clientHeight = target.clientHeight;

                setScrollOffsets(prev => {
                  const next = [...prev];
                  next[colIdx] = scrollTop;
                  return next;
                });

                // Infinite scroll: auto load next 10 nodes when reaching near bottom of loaded slice
                if (scrollTop + clientHeight >= scrollHeight - 120) {
                  setVisibleCounts(prev => {
                    const next = [...prev];
                    const currentVisible = next[colIdx] || 20;
                    const totalNodes = sortedColumns[colIdx]?.length || 0;
                    if (currentVisible < totalNodes) {
                      next[colIdx] = Math.min(totalNodes, currentVisible + 10);
                    }
                    return next;
                  });
                }
              }}
            >
              <div className="relative w-full" style={{ height: innerHeight }}>
                {col.map((node, rowIdx) => {
                  if (!node || !node.id) return null;
                  const { icon: categoryIcon } = getCategoryStyles(node.category, node.name, resolvedTheme);
                  const logoUrl = logoForNode?.(node.category, node.name) ?? null;
                  // A recognised service with no brand art still says what it is (filesystem → a
                  // folder, AWS → a cloud) rather than falling back to the column's database mark.
                  const Icon =
                    (!logoUrl && node.category === "Source"
                      ? sourceIcon?.(node.name)
                      : null) ?? categoryIcon;
                  const isLocked = effectiveLockedSet.has(node.id);
                  const isHovered = hoveredNodeId === node.id;
                  const isRelated = !activePathIds || isLocked || isHovered ||
                    Array.from(node.pathIds).some(id => activePathIds.has(id));

                  const isDimmed = !isRelated;
                  const topPos = startYLocal + rowIdx * 80;

                  return (
                    <div
                      key={node.id}
                      data-title={`${COLUMN_HEADERS.find((column) => column.id === node.category)?.label ?? node.category}: ${node.name} (${nodeCount(node)})`}
                      title={`${node.name} (${nodeCount(node)})`}
                      className={`absolute flex items-center transition-all duration-300 cursor-pointer z-10 flow-node 
                        ${node.category.toLowerCase()} 
                        ${node.category === "Authorization" || isDecision ? node.name.toLowerCase().replace(/[^a-z0-9]+/g, "-") : ""}
                        ${isDimmed ? "dim" : "active"} 
                        ${isLocked ? "locked" : ""}
                        ${isDecision ? "decision" : "non-decision"}`}
                      style={{
                        left: 0,
                        top: isDecision ? topPos - 4 : topPos,
                        width: 130,
                        color: node.category === "Taxonomy" ? TAXONOMY_DIAGRAM_COLOR : undefined
                      }}
                      onClick={(e) => {
                        e.stopPropagation();
                        handleNodeClick(node);
                      }}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          handleNodeClick(node);
                        }
                      }}
                      onMouseEnter={() => { if (!hasLocked) setHoveredNodeId(node.id); }}
                      onMouseLeave={() => { if (!hasLocked) setHoveredNodeId(null); }}
                    >
                      {isDecision ? (
                        <>
                          <div className={`flow-icon ${logoUrl ? "has-logo" : ""}`}>
                            {logoUrl ? (
                              <img src={logoUrl} className="size-4 object-contain" alt="" />
                            ) : (
                              <Icon className="size-3.5" strokeWidth={2.5} />
                            )}
                          </div>
                          <div className="flow-txt">
                            <strong className="truncate text-xs font-semibold text-foreground">{node.name}</strong>
                            <span className="truncate text-xs text-muted-foreground font-medium">{nodeCount(node)}</span>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className={`flow-icon ${logoUrl ? "has-logo" : ""}`}>
                            {logoUrl ? (
                              <img src={logoUrl} className="size-5 object-contain" alt="" />
                            ) : (
                              <Icon className="size-4" strokeWidth={2.5} />
                            )}
                          </div>
                          <div className="flow-txt center">
                            <strong className="truncate text-xs font-semibold text-foreground w-full">{node.name}</strong>
                            <span className="text-xs text-muted-foreground font-medium">{nodeCount(node)}</span>
                          </div>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {(() => {
              const scrollOffset = scrollOffsets[colIdx] || 0;
              const totalNodes = sortedColumns[colIdx]?.length || 0;
              const bottomNodeIndex = Math.floor((scrollOffset + colHeight) / 80);
              const remainingCount = Math.max(0, totalNodes - bottomNodeIndex);

              if (remainingCount <= 0) return null;

              return (
                <button
                  type="button"
                  aria-label={`Show more ${columnHeaders[colIdx].label.toLowerCase()}`}
                  onClick={event => { event.stopPropagation(); scrollRefs.current[colIdx]?.scrollBy({ top: colHeight, behavior: "instant" }); }}
                  className="absolute text-xs font-bold text-muted-foreground bg-muted/60 border border-border/80 px-2.5 py-1 rounded-full hover:bg-muted hover:text-foreground"
                  style={{
                    left: cx - 45,
                    top: PADDING.top + colHeight + 4,
                    width: 90,
                    textAlign: 'center'
                  }}
                >
                  +{remainingCount} more
                </button>
              );
            })()}
          </div>
        );
      })}

      {/* Focused Route Card removed */}
    </div>
  );
}
