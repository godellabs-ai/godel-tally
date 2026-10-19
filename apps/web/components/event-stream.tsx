"use client";

import { useEffect, useRef, useState } from "react";
import { Activity, ChevronRight, Filter, RefreshCw, Search, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { CustomTable, type Column } from "@/components/ui/custom-table";
import { EventDetails, EventStatusBadge } from "./event-details";
import { tallyFetch } from "../lib/tally";
import { connectorTypeLabel } from "../lib/connector-catalog";
import { authorizationFilters, eventDestination, eventKinds, eventLabel, eventModels, eventPerson, eventProviders, eventStatus, sourceAddresses, type EventAuthorizationStatus, type EventRow, type EventStreamResponse } from "../lib/event-stream";
import { browserTimeZone, formatDate, formatDateTime, formatTime } from "../lib/datetime";

const defaults = { q: "", window: "all", kind: "", connector_id: "", outcome: "", from: "", until: "" };
const selectClass = "h-9 min-w-0 rounded-md border border-border bg-card px-2 text-xs text-foreground";


export function EventStream({ refreshToken = 0, status, onStatusChange }: { refreshToken?: number; status: EventAuthorizationStatus; onStatusChange: (status: EventAuthorizationStatus) => void }) {
  const [draft, setDraft] = useState(defaults);
  const [request, setRequest] = useState({ filters: defaults, status, page: 1, size: 100, sort: "newest", revision: 0 });
  if (request.status !== status) setRequest({ ...request, status, page: 1, revision: request.revision + 1 });
  const [result, setResult] = useState<{ key: string; data: EventStreamResponse } | null>(null);
  const [failure, setFailure] = useState<{ key: string; message: string } | null>(null);
  const [formError, setFormError] = useState("");
  const [detail, setDetail] = useState<EventRow | null>(null);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const snapshot = useRef<{ scope: string; value: number } | null>(null);
  const key = JSON.stringify([request, refreshToken]);
  const data = result?.data;
  const error = failure?.key === key ? failure.message : "";
  const loading = result?.key !== key && !error;

  useEffect(() => {
    const controller = new AbortController();
    const scope = JSON.stringify([request.filters, request.status, request.revision, refreshToken]);
    const anchor = snapshot.current?.scope === scope ? snapshot.current.value : Date.now();
    const params = new URLSearchParams({ page: String(request.page), page_size: String(request.size), sort: request.sort, snapshot: String(anchor), status: request.status });
    const filters = request.filters;
    for (const field of ["q", "kind", "connector_id", "outcome"] as const) if (filters[field]) params.set(field, filters[field]);
    if (filters.window === "custom") {
      if (filters.from) params.set("from", String(new Date(filters.from).getTime()));
      if (filters.until) params.set("until", String(new Date(filters.until).getTime()));
    } else if (filters.window !== "all") {
      params.set("from", String(anchor - Number(filters.window) * 60 * 60 * 1000));
    }
    async function load() {
      try {
        const response = await tallyFetch(`/event-stream?${params}`, { cache: "no-store", signal: controller.signal });
        if (!response.ok) throw new Error("Events are unavailable. Retry to load this page.");
        const next: EventStreamResponse = await response.json();
        if (!Array.isArray(next.items) || !Array.isArray(next.sources) || !Array.isArray(next.findings) || !Number.isFinite(next.total) || !Number.isFinite(next.snapshot)) throw new Error("Events are unavailable. Retry to load this page.");
        if (!controller.signal.aborted) { snapshot.current = { scope, value: next.snapshot }; setResult({ key, data: next }); setFailure(null); }
      } catch (cause) {
        if (!controller.signal.aborted) setFailure({ key, message: cause instanceof Error ? cause.message : "Events are unavailable." });
      }
    }
    void load();
    return () => controller.abort();
  }, [key, request, refreshToken]);

  function refresh() { snapshot.current = null; setRequest(old => ({ ...old, page: 1, revision: old.revision + 1 })); }
  function apply(filters: typeof defaults) {
    if (filters.window === "custom" && (!filters.from || !filters.until || new Date(filters.from) > new Date(filters.until))) {
      setFormError("Choose a start and end time, with the end after the start."); return;
    }
    setFormError(""); snapshot.current = null;
    setRequest(old => ({ ...old, filters, page: 1, revision: old.revision + 1 }));
  }
  const rows: EventRow[] = (data?.items ?? []).map(event => ({ event, findings: data?.findings.filter(f => f.observation_id === event.observation_id) ?? [], connector: data?.sources.find(source => source.connector_id === event.connector.instance_id)?.label ?? connectorTypeLabel(event.connector.connector_type) }));
  const active = request.status !== "all" || Object.entries(request.filters).some(([field, value]) => value !== defaults[field as keyof typeof defaults]);
  const columns: Column<EventRow>[] = [
    { header: "Date", sortKey: "observed_at", className: "w-[145px]", cell: ({ event }) => <time dateTime={event.observed_at} title={`${formatDateTime(event.observed_at)} (${browserTimeZone()})`} className="text-xs tabular-nums"><span className="block font-medium">{formatDate(event.observed_at)}</span><span className="mt-1 block text-[11px] text-muted-foreground">{formatTime(event.observed_at)}</span></time> },
    { header: "Authorization", className: "w-[180px]", cell: row => <EventStatusBadge status={eventStatus(row)}/> },
    { header: "Person", className: "w-[210px]", cell: ({ event }) => <div className="flex min-w-0 items-center gap-2.5"><span className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-primary/8 text-primary"><UserRound className="size-3.5"/></span><Cell primary={eventPerson(event)} fallback="Not identified" secondary={event.actor?.identity?.source_subject_kind === "source_user_id" && !event.actor.identity.email ? "Source user ID" : undefined}/></div> },
    { header: "Endpoint", className: "w-[195px]", cell: ({ event }) => <Cell primary={event.actor?.hostname ?? sourceAddresses(event)[0]} secondary={event.actor?.hostname ? sourceAddresses(event).join(" · ") || "IP not reported" : event.actor?.workload?.workload_name ?? event.workload?.workload_name} mono fallback="Endpoint not reported"/> },
    { header: "AI provider / Model", className: "w-[210px]", cell: row => <Cell primary={eventProviders(row).join(", ")} secondary={eventModels(row).join(", ") || "Model not reported"} fallback="Provider not identified"/> },
    { header: "Destination", className: "w-[195px]", cell: ({ event }) => <Cell primary={eventDestination(event)} secondary={event.destination?.port ? `Port ${event.destination.port}` : event.destination?.ip && event.destination.ip !== eventDestination(event) ? event.destination.ip : undefined} mono fallback="Not reported"/> },
    { header: "Connector", className: "w-[190px]", cell: row => <Cell primary={row.connector} secondary={connectorTypeLabel(row.event.connector.connector_type)}/> },
    { header: <span className="sr-only">Details</span>, className: "w-12 !px-2", cell: row => <button type="button" aria-label={`View event ${row.event.observation_id}`} title="View activity details" onClick={event => { event.stopPropagation(); setDetail(row); }} className="rounded-md p-1.5 text-muted-foreground hover:bg-muted hover:text-primary focus-visible:outline-2 focus-visible:outline-primary"><ChevronRight className="size-4"/></button> },
  ];
  const filters = <div className="w-full space-y-3">
    <div role="group" aria-label="Authorization status" className="flex flex-wrap gap-1">
      {authorizationFilters.map(filter => <button key={filter.value} type="button" aria-pressed={status === filter.value} onClick={() => onStatusChange(filter.value)} className={`rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors ${status === filter.value ? "border-primary bg-primary text-primary-foreground shadow-xs" : "border-transparent text-muted-foreground hover:bg-muted hover:text-foreground"}`}>{filter.label}</button>)}
    </div>
    <form aria-label="Event filters" onSubmit={event => { event.preventDefault(); apply(draft); }} className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-48 flex-1"><Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground"/><Input aria-label="Search events" maxLength={256} placeholder="Search person, hostname, IP, destination, or model…" value={draft.q} onChange={event => setDraft({ ...draft, q: event.target.value })} className="h-9 bg-card pl-9 text-xs"/></div>
        <Button type="submit" size="sm">Apply filters</Button>
        <Button type="button" size="sm" variant="outline" aria-expanded={filtersOpen} onClick={() => setFiltersOpen(!filtersOpen)}><Filter className="size-3.5"/>Filters</Button>
        <Button type="button" size="sm" variant="ghost" onClick={() => { onStatusChange("all"); setDraft(defaults); apply(defaults); }}>Reset filters</Button>
        <Button type="button" size="sm" variant="outline" onClick={refresh} aria-label="Refresh events"><RefreshCw className={`size-3.5 ${loading ? "animate-spin" : ""}`}/></Button>
      </div>
      {filtersOpen ? <div className="flex flex-wrap gap-3 border-t border-border/60 pt-3">
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Time range<select aria-label="Time range" className={selectClass} value={draft.window} onChange={event => setDraft({ ...draft, window: event.target.value })}><option value="all">All retained events</option><option value="24">Last 24 hours</option><option value="168">Last 7 days</option><option value="720">Last 30 days</option><option value="custom">Custom range</option></select></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Event type<select aria-label="Event type" className={selectClass} value={draft.kind} onChange={event => setDraft({ ...draft, kind: event.target.value })}><option value="">All event types</option>{eventKinds.map(kind => <option key={kind} value={kind}>{eventLabel(kind)}</option>)}</select></label>
        <label className="flex max-w-full flex-col gap-1 text-xs text-muted-foreground">Connector<select aria-label="Connector" className={`${selectClass} max-w-72`} value={draft.connector_id} onChange={event => setDraft({ ...draft, connector_id: event.target.value })}><option value="">All connectors</option>{draft.connector_id && !data?.sources.some(source => source.connector_id === draft.connector_id) ? <option value={draft.connector_id}>{draft.connector_id}</option> : null}{data?.sources.map(source => <option key={source.connector_id} value={source.connector_id}>{source.label}</option>)}</select></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Source outcome<Input className="h-9 w-40 bg-card text-xs" maxLength={256} placeholder="Action, result, code…" value={draft.outcome} onChange={event => setDraft({ ...draft, outcome: event.target.value })}/></label>
        <label className="flex flex-col gap-1 text-xs text-muted-foreground">Order<select aria-label="Order" className={selectClass} value={request.sort} onChange={event => setRequest(old => ({ ...old, sort: event.target.value, page: 1 }))}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select></label>
        {draft.window === "custom" ? <><label className="flex flex-col gap-1 text-xs text-muted-foreground">From (local time)<Input type="datetime-local" value={draft.from} onChange={event => setDraft({ ...draft, from: event.target.value })}/></label><label className="flex flex-col gap-1 text-xs text-muted-foreground">To (local time)<Input type="datetime-local" value={draft.until} onChange={event => setDraft({ ...draft, until: event.target.value })}/></label></> : null}
      </div> : null}
      {formError ? <p role="alert" className="text-xs text-destructive">{formError}</p> : null}
    </form>
    {active ? <p className="text-[11px] text-muted-foreground">Filters applied · Times shown in your local timezone</p> : null}
    {error ? <div role="alert" className="rounded-lg border border-destructive/20 bg-destructive/5 p-3 text-xs text-destructive">{error} <button className="underline" onClick={() => setRequest(old => ({ ...old, revision: old.revision + 1 }))}>Retry</button></div> : null}
    {loading ? <span role="status" className="sr-only">Loading activity…</span> : null}
  </div>;
  return <>
    <CustomTable<EventRow> icon={<Activity className="size-4"/>} title="Findings" subtitle="Investigate AI activity by person, endpoint, and service."
      className="relative min-w-0" tableClassName="min-w-[1370px] table-fixed [&_td]:px-4 [&_th]:px-4" filters={filters}
      data={loading || error ? [] : rows} columns={columns} keyExtractor={row => row.event.observation_id}
      onRowClick={setDetail} rowClassName={row => detail?.event.observation_id === row.event.observation_id ? "bg-primary/5" : undefined}
      sortKey="observed_at" sortDir={request.sort === "oldest" ? "asc" : "desc"} onSort={() => setRequest(old => ({ ...old, sort: old.sort === "newest" ? "oldest" : "newest", page: 1 }))}
      currentPage={data?.page ?? 1} totalPages={data?.total_pages ?? 1} totalItemsCount={data?.total ?? 0} pageSize={request.size} pageSizeOptions={[100, 250, 500]} itemsName="events"
      onPageChange={page => setRequest(old => ({ ...old, page }))} onPageSizeChange={size => setRequest(old => ({ ...old, size, page: 1 }))}
      emptyStateTitle={loading ? "Loading activity…" : error ? "Activity unavailable" : "No events match these filters"}
      emptyStateDescription={loading ? "Fetching the matching events." : error ? "Your filters are preserved. Retry to load the table." : "Try a wider time range or reset filters."}/>
    <EventDetails row={detail} onClose={() => setDetail(null)} onInvestigate={query => { setDetail(null); onStatusChange("all"); const filters = { ...defaults, q: query }; setDraft(filters); apply(filters); }}/>
  </>;
}
function Cell({ primary, secondary, mono, fallback = "Not reported" }: { primary?: string; secondary?: string; mono?: boolean; fallback?: string }) {
  return <div className="min-w-0"><span className={`block truncate text-xs ${primary ? "font-semibold text-foreground" : "font-normal text-muted-foreground"} ${mono && primary ? "font-mono text-[11px]" : ""}`} title={primary}>{primary || fallback}</span>{secondary ? <span className="mt-1 block truncate text-[11px] text-muted-foreground" title={secondary}>{secondary}</span> : null}</div>;
}
