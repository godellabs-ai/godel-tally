"use client";
import Link from "next/link";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { formatDateTime } from "@/lib/datetime";
import { IdentityCorrections, type IdentityCorrection } from "@/components/identity-corrections";
import { returnToSignIn } from "@/lib/session";

interface Fact {
  fact_id: string; source_entity_id: string; observation_id: string; connector_instance_id: string;
  observed_at: string; last_seen?: string; received_at: string; valid_until: string | null; retired: boolean; source_retired_at?: string | null; source_last_refresh?: string | null; source_scope: string;
  attributes: { associated_user?: { email?: string; display_label?: string; source_subject?: string }; device_id?: string; identity_status?: string; device_key_kind?: string; reported_at?: string | null; hostname?: string; display_name?: string; addresses?: string[]; address_facts?: Array<{address:string;role:string;valid_from:string;valid_until:string|null;network_key:string|null}>; os?: string; connector_type: string; device_key?: string; identity?: { email?: string; source_subject?: string; display_label?: string }; role?: string; identifiers?: Array<{kind:string;value:string}> };
}
interface Record { entity_id: string; entity_kind: string; first_seen: string; last_seen: string; facts: Fact[] }

function Inventory() {
  const params = useSearchParams();
  const [kind, setKind] = useState(params.get("kind") === "user" ? "user" : "device"); const [query, setQuery] = useState(params.get("q") ?? "");
  const [corrections,setCorrections]=useState<IdentityCorrection[]>([]);
  const [records, setRecords] = useState<Record[]>([]); const [next, setNext] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null); const [loading, setLoading] = useState(true);
  const load = useCallback(async (cursor: string | null, signal?: AbortSignal) => {
    setLoading(true); setError(null);
    try {
      const search = new URLSearchParams({kind, q: query, limit: "50"}); if (cursor) search.set("after",cursor);
      const response = await fetch(`/api/v1/tally/inventory?${search}`,{signal});
      if (response.status === 401) { returnToSignIn(); return; }
      if (!response.ok) throw new Error("Inventory could not be loaded.");
      const data = await response.json() as {records:Record[];next_cursor:string|null;corrections?:IdentityCorrection[]};
      setRecords(previous => cursor ? [...previous,...data.records] : data.records); setNext(data.next_cursor);setCorrections(data.corrections??[]);
    } catch (cause) { if (!signal?.aborted) setError(cause instanceof Error ? cause.message : "Inventory could not be loaded."); }
    finally { if (!signal?.aborted) setLoading(false); }
  },[kind,query]);
  useEffect(() => {const abort = new AbortController();const timer = setTimeout(() => void load(null,abort.signal),200);return () => {clearTimeout(timer);abort.abort();};},[load]);
  return <div className="space-y-6 p-6">
    <div><h1 className="text-2xl font-semibold">People & devices</h1><p className="mt-2 text-sm text-muted-foreground">Source-reported inventory, including devices with no AI activity. Address observations and assigned owners do not prove who made a request.</p></div>
    <div className="flex flex-wrap gap-3"><Button variant={kind === "device" ? "default" : "outline"} onClick={() => setKind("device")}>Devices</Button><Button variant={kind === "user" ? "default" : "outline"} onClick={() => setKind("user")}>People</Button><Input aria-label="Search inventory" placeholder="Search hostname, user or identifier…" value={query} onChange={e => setQuery(e.target.value)} className="max-w-md" /></div>
    <IdentityCorrections key={kind} records={records.map(r=>({id:r.entity_id,label:r.facts[0]?.attributes.hostname??r.facts[0]?.attributes.display_name??r.facts[0]?.attributes.identity?.email??r.facts[0]?.attributes.identity?.display_label??r.facts[0]?.attributes.identity?.source_subject??r.entity_id}))} corrections={corrections} onChanged={()=>void load(null)} />
    {error && <p role="alert" className="text-destructive">{error}</p>}
    {records.map(record => <article key={record.entity_id} className="space-y-3 rounded-lg border bg-card p-4">
      <h2 className="font-medium">{record.facts[0]?.attributes.hostname ?? record.facts[0]?.attributes.display_name ?? record.facts[0]?.attributes.identity?.email ?? record.facts[0]?.attributes.identity?.display_label ?? record.facts[0]?.attributes.identity?.source_subject ?? record.entity_id}</h2>
      <p className="text-xs text-muted-foreground">{record.entity_kind==="device"&&record.facts.every(f=>f.attributes.identity_status==="provisional")?"Unresolved device observation · ":""}First seen {formatDateTime(record.first_seen)} · Last seen {formatDateTime(record.last_seen)} · {record.facts.length} source facts</p>
      <Link href={`/?q=${encodeURIComponent(record.facts[0]?.attributes.hostname ?? record.facts[0]?.attributes.display_name ?? record.facts[0]?.attributes.identity?.email ?? record.facts[0]?.attributes.identity?.source_subject ?? record.entity_id)}#findings`} className="block text-xs text-primary underline">Search related activity</Link>
      {record.facts.map(fact => <details key={fact.fact_id} className="rounded border p-3 text-xs">
        <summary className="cursor-pointer">{fact.attributes.connector_type} · {formatDateTime(fact.observed_at)}{fact.source_retired_at ? " · Missing from latest complete sync" : fact.retired ? " · Retired" : fact.valid_until && Date.parse(fact.valid_until) < Date.now() ? " · Expired" : ""}</summary>
        <dl className="mt-3 grid grid-cols-2 gap-2"><dt>Hostname</dt><dd>{fact.attributes.hostname ?? "Unavailable"}</dd><dt>Reported addresses</dt><dd>{fact.attributes.addresses?.join(", ") || "Unavailable"}</dd><dt>OS</dt><dd>{fact.attributes.os ?? "Unavailable"}</dd><dt>Related source user</dt><dd>{fact.attributes.associated_user?.email ?? fact.attributes.associated_user?.display_label ?? fact.attributes.associated_user?.source_subject ?? "Unavailable"}</dd><dt>Identity role</dt><dd>{fact.attributes.role?.replaceAll("_"," ") ?? "Unavailable"}</dd><dt>Valid until</dt><dd>{fact.valid_until ? formatDateTime(fact.valid_until) : "No source-authoritative expiry supplied"}</dd><dt>Source report / check-in</dt><dd>{fact.attributes.reported_at ? formatDateTime(fact.attributes.reported_at) : "Unavailable"}</dd><dt>Last complete sync</dt><dd>{fact.source_last_refresh ? formatDateTime(fact.source_last_refresh) : "Not an inventory snapshot source"}</dd><dt>Received</dt><dd>{formatDateTime(fact.received_at)}</dd><dt>Source scope</dt><dd className="break-all">{fact.source_scope}</dd><dt>Source event</dt><dd className="break-all">{fact.observation_id}</dd></dl>
        {fact.attributes.device_id && <Link href={`/inventory?q=${fact.attributes.device_id}`} className="mt-2 block text-primary underline">View associated device</Link>}
        {!!fact.attributes.address_facts?.length&&<div className="mt-2 space-y-1">{fact.attributes.address_facts.map((address,index)=><p key={`${address.address}:${index}`}>{address.address} · {address.role.replaceAll("_"," ")} · observed {formatDateTime(address.valid_from)}{address.valid_until?` through ${formatDateTime(address.valid_until)}`:" · no source-authoritative expiry"}</p>)}</div>}
        {!!fact.attributes.identifiers?.length && <div className="mt-2 space-y-1">{fact.attributes.identifiers.map(id => <p key={`${id.kind}:${id.value}`} className="break-all">{id.kind}: {id.value}</p>)}</div>}
      </details>)}
    </article>)}
    {loading && <p role="status">Loading inventory…</p>}
    {!loading && !error && !records.length && <p className="text-sm text-muted-foreground">No matching source inventory yet. Connect an endpoint, network or MDM source and sync it.</p>}
    {next && <Button variant="outline" disabled={loading} onClick={() => void load(next)}>Load more</Button>}
  </div>;
}
export default function InventoryPage() { return <Suspense fallback={<p className="p-6">Loading inventory…</p>}><Inventory /></Suspense>; }
