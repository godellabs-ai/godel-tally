"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "./ui/button";
import { formatDateTime } from "../lib/datetime";
import { returnToSignIn } from "../lib/session";

interface Activity {
  observation_id: string; observed_at: string; received_at: string;
  connector: { instance_id: string; connector_type: string; source_lineage_id?: string };
  actor: { identity?: { email?: string; source_subject?: string }; hostname?: string; source_ip?: string; device_key?: string; request_client?: { name?: string; agent_id?: string } };
  destination: { host?: string; ip?: string; port?: number };
  process: { executable?: string; pid?: string; unique_id?: string; started_at?: string; parent_executable?: string; parent_pid?: string };
  agent: { name?: string; attribution_confidence?: string; attribution_basis?: string };
  enrichment?: { device: { device_id: string | null; hostname: string | null; status: string; reason: string; evidence: string[]; rule: string }; process?: { status: string; process: Activity["process"] | null; process_account: Activity["actor"]["identity"] | null; observation_id: string; reason: string }; related_users: Array<{ user_id: string; role: string; connector_instance_id: string; observation_id: string; valid_from: string; valid_until: string | null }> };
  source_revisions?: Array<{context: unknown; conflicts:string[]; created_at:string}>;
  fields?: { [field: string]: { basis: string; dataset: string; source_field: string; observed_at: string; rule: string | null } };
  model: string | null; user_role: string | null; source: unknown;
}

export function FindingActivity({ findingId, observationId }: { findingId: string; observationId?: string }) {
  const [items, setItems] = useState<Activity[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async (cursor: string | null, signal?: AbortSignal) => {
    setLoading(true); setError(null);
    try {
      const params = new URLSearchParams({ limit: "25" }); if (observationId) params.set("observation_id", observationId); if (cursor) params.set("before", cursor);
      const response = await fetch(`/api/v1/tally/findings/${encodeURIComponent(findingId)}/activity?${params}`, { signal });
      if (response.status === 401) { returnToSignIn(); return; }
      if (!response.ok) throw new Error("Activity could not be loaded. Try again.");
      const data = await response.json() as { items: Activity[]; next_cursor: string | null };
      setItems(previous => cursor ? [...previous, ...data.items] : data.items); setNext(data.next_cursor);
    } catch (cause) { if (!signal?.aborted) setError(cause instanceof Error ? cause.message : "Activity could not be loaded."); }
    finally { if (!signal?.aborted) setLoading(false); }
  }, [findingId, observationId]);
  useEffect(() => { const abort = new AbortController(); const timer = setTimeout(() => void load(null, abort.signal), 0); return () => { clearTimeout(timer); abort.abort(); }; }, [load]);
  return <section className="space-y-3" aria-label="Linked activity">
    <h3 className="text-sm font-semibold">Linked activity</h3>
    <p className="text-xs text-muted-foreground">Each record keeps the source-reported user, device and process together. Client hints and device owners do not establish who ran a request.</p>
    {items.map(item => <article key={item.observation_id} className="space-y-2 rounded-md border p-3 text-xs">
      <div className="font-medium">{item.actor.identity?.email ?? item.actor.identity?.source_subject ?? "User unavailable"} · {item.actor.hostname ?? "Device name unavailable"}</div>
      <dl className="grid grid-cols-2 gap-x-3 gap-y-1">
        <dt>Process</dt><dd>{item.process.executable ?? "Unavailable"}{item.process.pid ? ` · PID ${item.process.pid}` : ""}</dd>
        <dt>Process identity</dt><dd className="break-all">{item.process.unique_id ?? (item.process.started_at ? `Started ${formatDateTime(item.process.started_at)}` : "Start time / unique ID unavailable")}</dd>
        <dt>Parent process</dt><dd>{item.process.parent_executable ?? "Unavailable"}{item.process.parent_pid ? ` · PID ${item.process.parent_pid}` : ""}</dd>
        <dt>Agent signature</dt><dd>{item.agent.name ?? "Unavailable"}</dd>
        <dt>Source address</dt><dd>{item.actor.source_ip ?? "Unavailable"}</dd>
        <dt>Destination</dt><dd className="break-all">{item.destination.host ?? item.destination.ip ?? "Unavailable"}{item.destination.port ? `:${item.destination.port}` : ""}</dd>
        <dt>Model from this event</dt><dd>{item.model ?? "Unavailable"}{item.model && item.fields?.model ? ` · ${item.fields.model.basis.replaceAll("_", " ")}` : ""}</dd>
        <dt>Identity role</dt><dd>{item.user_role?.replaceAll("_", " ") ?? "Source-reported actor"}</dd>
        <dt>Client hint</dt><dd>{item.actor.request_client?.name?.replaceAll("_", " ") ?? "Unavailable"}</dd>
        <dt>Event time</dt><dd>{formatDateTime(item.observed_at)}</dd>
        <dt>Received</dt><dd>{formatDateTime(item.received_at)}</dd>
        <dt>Source</dt><dd className="break-all">{item.connector.connector_type}</dd>
      </dl>
      {item.source_revisions?.some(revision=>revision.conflicts.length>0)&&<p className="text-xs text-destructive">Source revisions disagree. Review the evidence before relying on this attribution.</p>}
      {item.enrichment?.process && <p className="text-xs text-muted-foreground">Process enrichment: {item.enrichment.process.status} · {item.enrichment.process.process?.executable ?? "Unresolved"} · {item.enrichment.process.reason}</p>}
      {item.enrichment && <div className="rounded border p-2 text-muted-foreground"><p>Inventory: {item.enrichment.device.status} · {item.enrichment.device.hostname ?? "No canonical device label"}</p><p>{item.enrichment.device.reason}</p>{item.enrichment.related_users.map(user => <p key={`${user.user_id}:${user.role}:${user.connector_instance_id}:${user.observation_id}`}>{user.role.replaceAll("_", " ")}: {user.user_id} · supporting relationship, not a request actor</p>)}</div>}
      {item.agent.attribution_basis && <p className="text-muted-foreground">{item.agent.attribution_confidence ?? "Source-reported"}: {item.agent.attribution_basis}</p>}
      <details><summary className="cursor-pointer">Source evidence</summary><pre className="mt-2 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify({ observation_id: item.observation_id, connector: item.connector, receipt: item.source, field_evidence: item.fields, source_revisions:item.source_revisions }, null, 2)}</pre></details>
    </article>)}
    {loading && <p role="status" className="text-xs text-muted-foreground">Loading activity…</p>}
    {error && <p role="alert" className="text-xs text-destructive">{error}</p>}
    {!loading && !error && !items.length && <p className="text-xs text-muted-foreground">No linked activity is available. Older aggregate finding labels cannot reconstruct which user, device and process occurred together.</p>}
    {error ? <Button variant="outline" size="sm" onClick={() => void load(items.length ? next : null)}>Retry</Button> : next && <Button variant="outline" size="sm" disabled={loading} onClick={() => void load(next)}>Load more activity</Button>}
  </section>;
}
