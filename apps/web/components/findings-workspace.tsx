"use client";

import {
  AlertTriangle,
  Ban,
  Bot,
  Cable,
  Check,
  CheckCircle2,
  Clock3,
  MapPin,
  Monitor,
  Search,
  UserRound,
} from "lucide-react";
import { useMemo, useState, type CSSProperties, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Drawer, DrawerContent, DrawerDescription, DrawerTitle } from "@/components/ui/drawer";
import { Input } from "@/components/ui/input";
import { Pagination } from "@/components/ui/pagination";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  getGovernanceFindings,
  setRegistrySanctions,
  type GovernanceFinding,
  type GovernanceFindingsResponse,
} from "../lib/tally";
import { FindingActivity } from "./finding-activity";
import { formatDateTime } from "../lib/datetime";

export type FindingsView = "unsanctioned" | "authorization" | "sanctioned";

// Keep the column definition independent of the host application's Tailwind scan.
// Embedding applications can consume this component from outside its app directory, so unique
// arbitrary-value utilities are not guaranteed to be emitted there.
const AUTHORIZATION_GRID: CSSProperties = {
  gridTemplateColumns: "36px minmax(180px, 1fr) minmax(180px, 1fr) minmax(150px, 0.8fr) 110px 210px",
  minWidth: "980px",
};
const STANDARD_GRID: CSSProperties = {
  gridTemplateColumns: "minmax(180px, 1fr) minmax(180px, 1fr) minmax(150px, 0.8fr) 110px 140px",
  minWidth: "900px",
};
const AUTHORIZATION_IDENTITY_GRID: CSSProperties = {
  gridTemplateColumns: "36px minmax(180px, 1fr) minmax(180px, 1fr) minmax(150px, 0.8fr) minmax(180px, 0.9fr) 110px 210px",
  minWidth: "1160px",
};
const STANDARD_IDENTITY_GRID: CSSProperties = {
  gridTemplateColumns: "minmax(180px, 1fr) minmax(180px, 1fr) minmax(150px, 0.8fr) minmax(180px, 0.9fr) 110px 140px",
  minWidth: "1080px",
};

function findingGrid(actionable: boolean, showUserIdentity: boolean): CSSProperties {
  if (actionable) return showUserIdentity ? AUTHORIZATION_IDENTITY_GRID : AUTHORIZATION_GRID;
  return showUserIdentity ? STANDARD_IDENTITY_GRID : STANDARD_GRID;
}

export function FindingsWorkspace({
  initialData,
  initialView,
  view: controlledView,
  onViewChange,
  fixedView,
  canWrite = true,
  showUserIdentity = false,
  showDetailNavigation = false,
  externalSearch,
  hideSearch = false,
  onChanged,
  renderSupplementalContent,
}: {
  initialData: GovernanceFindingsResponse;
  initialView: FindingsView;
  /** Host-controlled status while preserving the status tabs and table state. */
  view?: FindingsView;
  onViewChange?: (view: FindingsView) => void;
  /** Locks the workspace to one host-owned tab and hides Tally's nested status tabs. */
  fixedView?: FindingsView;
  canWrite?: boolean;
  /** Embedded view: expose the endpoint-directory identity attached to each finding. */
  showUserIdentity?: boolean;
  /** Embedded Gate view: use the host drawer's section navigation, matching Activity drawers. */
  showDetailNavigation?: boolean;
  /** Host-owned search field, used when this table is embedded under a shared heading. */
  externalSearch?: string;
  hideSearch?: boolean;
  onChanged?: (data?: GovernanceFindingsResponse) => void;
  /** Optional host-owned content rendered after the Tally finding table. */
  renderSupplementalContent?: (view: FindingsView) => ReactNode;
}) {
  const [data, setData] = useState(initialData);
  const [view, setView] = useState<FindingsView>(initialView);
  const activeView = fixedView ?? controlledView ?? view;
  const [viewSnapshot, setViewSnapshot] = useState(activeView);
  const [query, setQuery] = useState("");
  const searchQuery = externalSearch ?? query;
  const [searchSnapshot, setSearchSnapshot] = useState(searchQuery);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<GovernanceFinding | null>(null);
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [decisionError, setDecisionError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [initialDataSnapshot, setInitialDataSnapshot] = useState(initialData);

  if (activeView !== viewSnapshot) {
    setViewSnapshot(activeView);
    setSelected(new Set());
    setCurrentPage(1);
  }

  // Embedded hosts commonly render once with an empty loading value and replace it after their
  // client request finishes. Adjust during render so descendants never render the stale snapshot.
  if (initialData !== initialDataSnapshot) {
    setInitialDataSnapshot(initialData);
    setData(initialData);
    setCurrentPage(1);
  }
  if (searchQuery !== searchSnapshot) {
    setSearchSnapshot(searchQuery);
    setSelected(new Set());
    setCurrentPage(1);
  }

  const rows = useMemo(() => {
    const source = activeView === "unsanctioned" ? data.unsanctioned : activeView === "authorization" ? data.authorization_queue : data.sanctioned;
    const needle = searchQuery.toLowerCase();
    return source.filter((item) => `${item.provider.name} ${providerPresentation(item).primary} ${item.model?.name ?? ""} ${item.model_version ?? ""} ${item.endpoints.map((endpoint) => formatHost(endpoint)).join(" ")} ${item.destinations.map((destination) => formatHost(destination)).join(" ")} ${item.users.map((user) => `${user.value} ${user.email ?? ""}`).join(" ")} ${item.connectors.map((connector) => connector.name).join(" ")} ${(item.clients ?? []).map((client) => `${clientLabel(client.name)} ${client.agent_id ?? ""}`).join(" ")}`.toLowerCase().includes(needle));
  }, [activeView, data, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const paginatedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return rows.slice(start, start + pageSize);
  }, [rows, safePage, pageSize]);
  const visibleViews: FindingsView[] = fixedView
    ? [fixedView]
    : ["unsanctioned", "authorization", "sanctioned"];

  async function applySanction(findings: GovernanceFinding[], sanctioned: boolean) {
    if (!canWrite) return;
    const providerIds = [...new Set(findings.filter((item) => item.provider.sanctioned !== sanctioned).map((item) => item.provider.provider_id))];
    const modelIds = [...new Set(findings.filter((item) => item.model && item.model.sanctioned !== sanctioned).map((item) => item.model?.model_id).filter(Boolean) as string[])];
    if (!providerIds.length && !modelIds.length) return;
    setPending(true);
    setNotice(null);
    setDecisionError(null);
    const result = await setRegistrySanctions(providerIds, modelIds, sanctioned);
    if (!result.ok) { setNotice(result.error); setDecisionError(result.error); setPending(false); return; }

    const refreshed = await getGovernanceFindings();
    if (refreshed) {
      setData(refreshed);
    }
    setPending(false);
    setSelected(new Set());
    setDetail(null);
    setNotice(refreshed
      ? `Registry decision saved as ${sanctioned ? "Sanctioned" : "Unsanctioned"}.`
      : "Registry decision saved. Refresh findings to see the updated status.");
    onChanged?.(refreshed ?? undefined);
  }

  const selectedFindings = rows.filter((item) => selected.has(item.finding_id));

  return (
    <div className="space-y-6">
      <Tabs value={activeView} onValueChange={(value) => { if (!fixedView) { setView(value as FindingsView); onViewChange?.(value as FindingsView); } setSelected(new Set()); setCurrentPage(1); }}>
        {!fixedView ? <div className="w-full overflow-x-auto scrollbar-hide">
          <TabsList className="flex h-auto w-full min-w-max flex-nowrap items-center justify-start gap-1 rounded-lg border border-border/80 bg-card p-1 shadow-2xs group-data-[orientation=horizontal]/tabs:h-auto">
            <TabsTrigger
              value="unsanctioned"
              className="group h-auto flex-none shrink-0 whitespace-nowrap gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-all duration-150 hover:bg-muted/70 hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-xs dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground cursor-pointer"
            >
              <AlertTriangle className="size-3.5 shrink-0 transition-transform duration-150 group-hover:scale-105" />
              <span>Unsanctioned</span>
            </TabsTrigger>
            <TabsTrigger
              value="authorization"
              className="group h-auto flex-none shrink-0 whitespace-nowrap gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-all duration-150 hover:bg-muted/70 hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-xs dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground cursor-pointer"
            >
              <Clock3 className="size-3.5 shrink-0 transition-transform duration-150 group-hover:scale-105" />
              <span>Authorization Queue</span>
            </TabsTrigger>
            <TabsTrigger
              value="sanctioned"
              className="group h-auto flex-none shrink-0 whitespace-nowrap gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold text-muted-foreground transition-all duration-150 hover:bg-muted/70 hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-xs dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground cursor-pointer"
            >
              <CheckCircle2 className="size-3.5 shrink-0 transition-transform duration-150 group-hover:scale-105" />
              <span>Sanctioned</span>
            </TabsTrigger>
          </TabsList>
        </div> : null}

        <Card className="mt-2 gap-0 overflow-hidden py-0">
          {(!hideSearch || (canWrite && selected.size > 0)) && <div className="flex flex-wrap items-center gap-3 border-b border-border p-4">
            {!hideSearch && <div className="relative min-w-60 flex-1"><Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" /><Input value={searchQuery} onChange={(event) => { setQuery(event.target.value); setSelected(new Set()); setCurrentPage(1); }} placeholder="Search providers, models, and endpoints…" className="pl-9" /></div>}
            {canWrite && selected.size ? (
              <div className="flex items-center gap-2">
                {activeView !== "sanctioned" && <Button
                  variant="outline"
                  size="sm"
                  disabled={pending}
                  onClick={() => void applySanction(selectedFindings, true)}
                  aria-label={`Sanction ${selected.size} selected findings`}
                  title="Sanction selected findings"
                  className="gap-1.5 border-emerald-600/30 bg-emerald-500/10 text-emerald-600 hover:border-emerald-600/50 hover:bg-emerald-500/20 hover:text-emerald-700 dark:border-emerald-500/30 dark:bg-emerald-500/15 dark:text-emerald-400 dark:hover:bg-emerald-500/25 dark:hover:text-emerald-300 font-semibold shadow-2xs"
                >
                  <Check className="size-3.5 text-emerald-600 dark:text-emerald-400" />
                  {selected.size}
                </Button>}
                {activeView !== "unsanctioned" && <Button
                  variant="outline"
                  size="sm"
                  disabled={pending}
                  onClick={() => void applySanction(selectedFindings, false)}
                  aria-label={`Unsanction ${selected.size} selected findings`}
                  title="Unsanction selected findings"
                  className="gap-1.5 border-destructive/30 bg-destructive/10 text-destructive hover:border-destructive/50 hover:bg-destructive/20 dark:border-destructive/30 dark:bg-destructive/15 dark:text-destructive dark:hover:bg-destructive/25 font-semibold shadow-2xs"
                >
                  <Ban className="size-3.5 text-destructive" />
                  {selected.size}
                </Button>}
              </div>
            ) : null}
          </div>}
          {notice ? <div role="status" className="border-b border-border bg-muted/20 px-4 py-2.5 text-xs text-muted-foreground">{notice}</div> : null}

          {visibleViews.map((tab) => (
            <TabsContent key={tab} value={tab} className="m-0 overflow-x-auto">
              <div
                className="grid items-center gap-3 border-b border-border bg-muted/25 px-4 py-2.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground"
                style={findingGrid(canWrite, showUserIdentity)}
              >
                {canWrite ? <input type="checkbox" aria-label="Select all visible findings" checked={paginatedRows.length > 0 && paginatedRows.every((item) => selected.has(item.finding_id))} onChange={() => setSelected(paginatedRows.every((item) => selected.has(item.finding_id)) ? new Set() : new Set(paginatedRows.map((item) => item.finding_id)))} className="size-4 accent-[var(--primary)]" /> : null}
                <span>Provider / endpoint</span><span>Model</span><span>Source connector</span>{showUserIdentity ? <span>User identity</span> : null}<span>Last observed</span><span>{canWrite ? "Action / context" : "Context"}</span>
              </div>
              <div className="divide-y divide-border">
                {paginatedRows.map((item) => <FindingRow key={item.finding_id} item={item} actionable={canWrite} showUserIdentity={showUserIdentity} selected={selected.has(item.finding_id)} pending={pending} onSelect={() => toggle(item.finding_id, selected, setSelected)} onOpen={() => { setDecisionError(null); setDetail(item); }} onSanction={(sanctioned) => void applySanction([item], sanctioned)} />)}
                {!rows.length ? <div className="p-12 text-center text-sm text-muted-foreground">{emptyMessage(tab)}</div> : null}
              </div>
            </TabsContent>
          ))}
          <Pagination
              currentPage={safePage}
              totalPages={totalPages}
              totalItems={rows.length}
              pageSize={pageSize}
              onPageChange={setCurrentPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setCurrentPage(1);
              }}
              pageSizeOptions={[10, 20, 50]}
              itemsName="findings"
            />
        </Card>
      </Tabs>
      {renderSupplementalContent?.(activeView)}

      <FindingDetails item={detail} open={Boolean(detail)} showNavigation={showDetailNavigation} canWrite={canWrite} pending={pending} decisionError={decisionError} onSanction={(sanctioned) => { if (detail) void applySanction([detail], sanctioned); }} onOpenChange={(open) => { if (!open) setDetail(null); }} />
    </div>
  );
}

function FindingRow({ item, actionable, showUserIdentity, selected, pending, onSelect, onOpen, onSanction }: { item: GovernanceFinding; actionable: boolean; showUserIdentity: boolean; selected: boolean; pending: boolean; onSelect: () => void; onOpen: () => void; onSanction: (sanctioned: boolean) => void }) {
  const provider = providerPresentation(item);
  const endpointCount = item.endpoints.length;
  const user = findingUserPresentation(item);
  return (
    <div
      className="grid items-center gap-3 px-4 py-3 text-xs hover:bg-muted/20"
      style={findingGrid(actionable, showUserIdentity)}
    >
      {actionable ? <input type="checkbox" aria-label={`Select ${provider.primary}`} checked={selected} onChange={onSelect} className="size-4 accent-[var(--primary)]" /> : null}
      <button type="button" onClick={onOpen} className="min-w-0 text-left"><span className="block truncate text-sm font-bold" title={provider.primary}>{provider.primary}</span><span className="block truncate text-[10px] capitalize text-muted-foreground">{provider.secondary}</span></button>
      <button type="button" onClick={onOpen} className="min-w-0 text-left"><span className="block truncate text-sm font-semibold">{item.model?.name ?? "Model not reported"}</span><span className="block truncate font-mono text-[10px] text-muted-foreground">{item.model_version ?? item.model?.family ?? "Provider usage"}</span></button>
      <button type="button" onClick={onOpen} className="min-w-0 text-left">
        {item.connectors.length ? item.connectors.map((connector) => (
          <span key={connector.connector_instance_id} className="block truncate text-sm font-semibold" title={connector.name}>{connector.name}</span>
        )) : <span className="block truncate text-sm font-semibold">Unknown source</span>}
        <span className="block text-[10px] text-muted-foreground">{item.users.length} users · {endpointCount} endpoints</span>
        {(item.clients ?? []).length ? <span className="block truncate text-[10px] text-muted-foreground">{[...new Set(item.clients?.map((client) => clientLabel(client.name)))].join(" · ")}</span> : null}
      </button>
      {showUserIdentity ? (
        <button type="button" onClick={onOpen} className="min-w-0 text-left">
          <span className="block truncate text-sm font-semibold" title={user.primary}>{user.primary}</span>
          <span className="block truncate text-[10px] text-muted-foreground">{user.secondary}</span>
        </button>
      ) : null}
      <span className="text-muted-foreground">{relativeTime(item.last_used_at)}</span>
      <div className="flex flex-col items-end gap-1">
        {actionable && <FindingDecisionControl item={item} pending={pending} onSanction={onSanction} />}
        <button type="button" onClick={onOpen} className="text-[11px] font-semibold text-primary hover:underline">
          {item.users.length} users · {endpointCount} hosts
        </button>
      </div>
    </div>
  );
}

function FindingDecisionControl({ item, pending, onSanction }: { item: GovernanceFinding; pending: boolean; onSanction: (sanctioned: boolean) => void }) {
  const name = `${providerPresentation(item).primary}${item.model ? ` ${item.model.name}` : ""}`;
  return <div className="flex items-center gap-1.5" onClick={(event) => event.stopPropagation()}>
    <Switch
      checked={item.status === "sanctioned"}
      disabled={pending}
      onCheckedChange={onSanction}
      aria-label={`${name}: ${item.status === "authorization_queue" ? "Undecided" : item.status}. Change to ${item.status === "sanctioned" ? "unsanctioned" : "sanctioned"}`}
    />
    {item.status === "authorization_queue" ? (
      <select
        value=""
        disabled={pending}
        onChange={(event) => onSanction(event.target.value === "true")}
        aria-label={`Decide ${name}`}
        title="Choose a decision for this undecided provider and model"
        style={{ width: 86 }}
        className="cursor-pointer bg-transparent text-[10px] font-semibold text-amber-700 dark:text-amber-400"
      >
        <option value="" disabled>Undecided</option>
        <option value="true">Sanctioned</option>
        <option value="false">Unsanctioned</option>
      </select>
    ) : <span className={`text-[10px] font-semibold ${item.status === "sanctioned" ? "text-emerald-700 dark:text-emerald-400" : "text-destructive"}`}>{item.status === "sanctioned" ? "Sanctioned" : "Unsanctioned"}</span>}
  </div>;
}

function findingUserPresentation(item: GovernanceFinding) {
  const [first, ...remaining] = item.users;
  if (!first) {
    return { primary: "Unknown user", secondary: "Identity not supplied" };
  }
  return {
    primary: first.email ?? first.value,
    secondary: remaining.length
      ? `${first.kind.replaceAll("_", " ")} · +${remaining.length} more`
      : first.kind.replaceAll("_", " "),
  };
}

function FindingDetails({ item, open, showNavigation, canWrite, pending, decisionError, onSanction, onOpenChange }: { item: GovernanceFinding | null; open: boolean; showNavigation: boolean; canWrite: boolean; pending: boolean; decisionError: string | null; onSanction: (sanctioned: boolean) => void; onOpenChange: (open: boolean) => void }) {
  const [current, setCurrent] = useState<GovernanceFinding | null>(item);
  if (item && item !== current) setCurrent(item);

  const provider = current ? providerPresentation(current) : null;
  if (!current || !provider) return <Drawer open={open} onOpenChange={onOpenChange} />;

  const evidenceLabel = current.evidence_kind === "resource_discovery" ? "Resource discovered" : current.evidence_kind === "network_activity" ? "Network activity" : "AI request";
  const status = findingStatusPresentation(current.status);
  const unsanctionedMessage = findingUnsanctionedMessage(current, provider.primary);

  return (
    <Drawer open={open} onOpenChange={onOpenChange}>
      <DrawerContent showTOC={showNavigation}>
        <div className="flex min-h-[72px] shrink-0 items-center border-b border-border/80 bg-card/95 py-3 pl-5 pr-12 backdrop-blur-xl">
          <div className="min-w-0">
            <DrawerTitle className="flex flex-wrap items-center gap-2.5">
              <span className="inline-flex min-w-0 items-center gap-1.5 text-sm font-bold text-foreground">
                <Bot className="size-4 shrink-0 text-primary" />
                <span className="truncate">{provider.primary}{current.model ? ` · ${current.model.name}` : ""}</span>
              </span>
              <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${status.badge}`}>
                <span className={`size-1.5 rounded-full ${status.dot}`} />
                {status.label}
              </span>
            </DrawerTitle>
            <DrawerDescription className="mt-1 text-xs">
              {evidenceLabel} first observed {formatDateTime(current.first_used_at)} · most recently {formatDateTime(current.last_used_at)}
            </DrawerDescription>
          </div>
        </div>

        <div className="custom-scrollbar min-w-0 flex-1 space-y-6 overflow-y-auto overflow-x-hidden wrap-anywhere bg-[#f7f7fb] px-5 py-4 pb-8 dark:bg-[#181821]">
          {canWrite && current.status === "authorization_queue" && (
            <section className="rounded-2xl border border-primary/20 bg-card p-4 shadow-xs">
              <h3 className="text-sm font-bold text-foreground">Authorization decision</h3>
              <p className="mt-1 text-xs text-muted-foreground">Decide whether this provider and model may be used.</p>
              <div className="mt-3"><FindingDecisionControl item={current} pending={pending} onSanction={onSanction} /></div>
              {decisionError && <p role="alert" className="mt-3 text-xs text-destructive">{decisionError}</p>}
            </section>
          )}
          {unsanctionedMessage ? (
            <div className="flex items-start gap-2.5 rounded-xl border border-red-500/30 bg-red-500/10 p-3.5 text-red-800 dark:text-red-300">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <p className="text-xs font-bold leading-relaxed">{unsanctionedMessage}</p>
            </div>
          ) : null}

          <FindingActivity key={current.finding_id} findingId={current.finding_id} />
          <DetailSection icon={Monitor} title="Endpoints" navigation={showNavigation}>{current.endpoints.length ? current.endpoints.map((endpoint) => <DetailRow key={`${endpoint.endpoint_host_id}-${endpoint.role}-${endpoint.port ?? 0}`} primary={formatHost(endpoint)} secondary={`${endpoint.role.replaceAll("_", " ")} · ${endpoint.kind.replace("_", " ")}`} />) : <EmptyDetail text="No source device or local AI service host was supplied by the connectors that observed this usage." />}</DetailSection>
          <DetailSection icon={MapPin} title="Destinations" navigation={showNavigation}>{current.destinations.length ? current.destinations.map((destination) => <DetailRow key={`${destination.destination_host_id}-${destination.port ?? 0}`} primary={formatHost(destination)} secondary={`Remote service · ${destination.kind.replace("_", " ")}`} />) : <EmptyDetail text="No remote service destination was supplied by the connectors that observed this usage." />}</DetailSection>
          <DetailSection icon={UserRound} title="Users" navigation={showNavigation}>{current.users.length ? current.users.map((user) => <DetailRow key={user.endpoint_user_id} primary={user.email ?? user.value} secondary={`${user.kind.replaceAll("_", " ")} · Last seen ${formatDateTime(user.last_seen)}`} />) : <EmptyDetail text="No user data was supplied by the connectors that observed this usage." />}</DetailSection>
          {(current.clients ?? []).length ? <DetailSection icon={Bot} title="Clients / frameworks" navigation={showNavigation}>{current.clients?.map((client) => <DetailRow key={`${client.connector_instance_id}-${client.name ?? ""}-${client.agent_id ?? ""}`} primary={clientLabel(client.name)} secondary={`${client.agent_id ? `Source-reported agent ID: ${client.agent_id} · ` : "Client hint, not a verified agent instance · "}${current.connectors.find((connector) => connector.connector_instance_id === client.connector_instance_id)?.name ?? "Source connector"} · Last seen ${formatDateTime(client.last_seen)}`} />)}</DetailSection> : null}
          {current.workloads.length ? <DetailSection icon={Bot} title="Workloads" navigation={showNavigation}>{current.workloads.map((workload) => <DetailRow key={`${workload.namespace_name}-${workload.workload_kind}-${workload.workload_name}-${workload.runtime_image ?? ""}`} primary={`${workload.namespace_name}/${workload.workload_name}`} secondary={`${workload.workload_kind.replaceAll("_", " ")}${workload.runtime_image ? ` · ${workload.runtime_image}` : ""}`} />)}</DetailSection> : null}
          <DetailSection icon={Cable} title="Sources" navigation={showNavigation}>{current.connectors.map((connector) => <DetailRow key={connector.connector_instance_id} primary={connector.name} secondary={connector.connector_type.replaceAll("_", " ")} />)}</DetailSection>
          <DetailSection icon={Bot} title="Evidence" navigation={showNavigation}><DetailRow primary={`${current.usage_count.toLocaleString()} observations`} secondary={`${evidenceLabel}${current.model_version ? ` · Model version ${current.model_version}` : ""}`} /></DetailSection>
        </div>
      </DrawerContent>
    </Drawer>
  );
}

function clientLabel(name: NonNullable<GovernanceFinding["clients"]>[number]["name"]) {
  const labels = { langchain: "LangChain", langgraph: "LangGraph", opencode: "OpenCode", cursor: "Cursor", claude_code: "Claude Code", codex: "Codex", openai_python: "OpenAI Python SDK", openai_node: "OpenAI Node SDK", curl: "curl" };
  return name ? labels[name] : "Source-reported agent";
}

function findingStatusPresentation(status: GovernanceFinding["status"]) {
  if (status === "unsanctioned") return { label: "Unsanctioned", badge: "border-red-500/25 bg-red-500/10 text-red-600 dark:text-red-400", dot: "bg-red-500" };
  if (status === "authorization_queue") return { label: "Needs authorization", badge: "border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-400", dot: "bg-amber-500" };
  return { label: "Sanctioned", badge: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400", dot: "bg-emerald-500" };
}

function findingUnsanctionedMessage(item: GovernanceFinding, providerName: string) {
  const providerUnsanctioned = item.violation_reasons.includes("provider_unsanctioned");
  const modelUnsanctioned = item.violation_reasons.includes("model_unsanctioned");
  if (providerUnsanctioned && modelUnsanctioned) return `${providerName} and ${item.model?.name ?? "this model"} are unsanctioned.`;
  if (providerUnsanctioned) return `${providerName} is unsanctioned.`;
  if (modelUnsanctioned) return `${item.model?.name ?? "This model"} is unsanctioned.`;
  return null;
}

function DetailSection({ icon: Icon, title, navigation, children }: { icon: typeof Bot; title: string; navigation: boolean; children: React.ReactNode }) { const sectionId = `drawer-sec-tally-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`; return <section id={navigation ? sectionId : undefined} data-drawer-section={navigation ? title : undefined} data-drawer-nav={navigation ? title : undefined} className="scroll-mt-4 rounded-2xl border border-border/75 bg-card/65 p-4 shadow-xs"><div className="flex items-center gap-2.5"><span className="flex size-7 shrink-0 items-center justify-center rounded-lg border border-border/50 bg-muted text-muted-foreground"><Icon className="size-4" /></span><h3 className="text-sm font-bold text-foreground">{title}</h3></div><div className="mt-3 divide-y divide-border/70 overflow-hidden rounded-xl border border-border/80 bg-background">{children}</div></section>; }
function DetailRow({ primary, secondary }: { primary: string; secondary: string }) { return <div className="px-4 py-3.5"><p className="break-all text-sm font-semibold text-foreground">{primary}</p><p className="mt-1 text-[11px] capitalize leading-relaxed text-muted-foreground">{secondary}</p></div>; }
function EmptyDetail({ text }: { text: string }) { return <p className="px-4 py-3.5 text-xs leading-relaxed text-muted-foreground">{text}</p>; }
function toggle(id: string, selected: Set<string>, setSelected: (value: Set<string>) => void) { const next = new Set(selected); if (next.has(id)) next.delete(id); else next.add(id); setSelected(next); }
function relativeTime(value: string) { const seconds = Math.max(0, (Date.now() - new Date(value).getTime()) / 1000); if (seconds < 60) return "Just now"; if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`; return `${Math.floor(seconds / 86400)}d ago`; }
function emptyMessage(view: FindingsView) { return view === "unsanctioned" ? "No unsanctioned provider or model usage has been observed." : view === "authorization" ? "No unknown providers or models need a sanction decision." : "Sanctioned usage will appear here after a connector observes it."; }

function providerPresentation(item: GovernanceFinding) {
  const destination = item.provider.catalog ? null : findingDestination(item);
  return destination
    ? { primary: destination, secondary: "Uncatalogued provider" }
    : { primary: item.provider.name, secondary: item.provider.category.replaceAll("_", " ") };
}

function findingDestination(item: GovernanceFinding) {
  const destination = item.destinations.find((candidate) => candidate.kind === "hostname")
    ?? item.destinations[0];
  if (!destination) return null;
  return destination.kind === "hostname" ? `https://${formatHost(destination)}` : formatHost(destination);
}

function formatHost(target: { kind: "hostname" | "ip_address"; value: string; port: number | null }) {
  if (!target.port) return target.value;
  const value = target.kind === "ip_address" && target.value.includes(":") ? `[${target.value}]` : target.value;
  return `${value}:${target.port}`;
}
