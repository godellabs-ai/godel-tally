"use client";
import { useState } from "react";
import { Search } from "lucide-react";
import { Pagination } from "@/components/ui/pagination";
import { Drawer, DrawerContent, DrawerTitle, DrawerDescription } from "@/components/ui/drawer";
import { entityKind, entityStatus, relativeSeen, estateReviewOptions, type EstateRecord, type EstateReviewAction } from "../lib/estate";
import { formatDateTime } from "../lib/datetime";

export type EstateReview = (record: EstateRecord, action: EstateReviewAction) => Promise<void>;
export function EstateRecordTable({ records, loading = false, onReview }: { records: EstateRecord[]; loading?: boolean; onReview?: EstateReview }) {
  const [saving, setSaving] = useState(false), [error, setError] = useState("");
  async function review(record: EstateRecord, action: EstateReviewAction) {
    setSaving(true); setError("");
    try { await onReview?.(record, action); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not save the review decision."); }
    finally { setSaving(false); }
  }
  const [query, setQuery] = useState(""), [kind, setKind] = useState(""), [status, setStatus] = useState("");
  const [page, setPage] = useState(1), [size, setSize] = useState(25), [selected, setSelected] = useState<string | null>(null);
  const filtered = records.filter(record => (!kind || record.detail.kind === kind) && (!status || entityStatus(record) === status)
    && [record.detail.name, record.detail.hostname, record.detail.connector_type, record.detail.platform].some(value => value?.toLowerCase().includes(query.trim().toLowerCase())));
  const pages = Math.max(1, Math.ceil(filtered.length / size)), current = Math.min(page, pages);
  const record = records.find(item => item.id === selected);
  return <div className="min-w-0" aria-label="Discovered inventory">
    <div className="flex flex-wrap items-center gap-3 p-4">
      <label className="flex min-w-48 flex-1 items-center gap-2 rounded-lg border border-border bg-card px-3 py-2"><Search className="size-4 text-muted-foreground"/><input className="min-w-0 flex-1 bg-transparent text-sm outline-none" aria-label="Search inventory" placeholder="Search inventory…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }}/></label>
      <select aria-label="Inventory type" className="rounded-lg border border-border bg-card p-2 text-sm" value={kind} onChange={event => { setKind(event.target.value); setPage(1); }}><option value="">All types</option>{[...new Set(records.map(item => item.detail.kind))].sort().map(value => <option key={value} value={value}>{entityKind(value)}</option>)}</select>
      <select aria-label="Inventory status" className="rounded-lg border border-border bg-card p-2 text-sm" value={status} onChange={event => { setStatus(event.target.value); setPage(1); }}><option value="">All statuses</option>{["Sanctioned", "Unsanctioned", "Unreviewed"].map(value => <option key={value}>{value}</option>)}</select>
    </div>
    <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="border-y border-border bg-muted/40 text-xs text-muted-foreground"><tr>{["Entity", "Type", "Status", "Source", "Last seen"].map(label => <th key={label} className="px-4 py-3 font-medium">{label}</th>)}</tr></thead>
      <tbody>{filtered.slice((current - 1) * size, current * size).map(item => <tr key={item.id} className="border-b border-border hover:bg-muted/30" data-inventory-id={item.id}>
        <td className="px-4 py-3"><button className="text-left font-medium hover:text-primary" onClick={() => { setSelected(item.id); setError(""); }}>{item.detail.name}</button>{item.detail.hostname ? <div className="text-xs text-muted-foreground">{item.detail.hostname}</div> : null}</td><td className="px-4 py-3">{entityKind(item.detail.kind)}</td>
        <td className="px-4 py-3"><span className={item.sanctioned === false ? "text-destructive" : item.sanctioned === true ? "text-pass" : "text-muted-foreground"}>{entityStatus(item)}</span></td><td className="px-4 py-3 text-muted-foreground">{item.detail.connector_type.replaceAll("_", " ")}</td><td className="whitespace-nowrap px-4 py-3 text-muted-foreground">{relativeSeen(item.last_seen)}</td>
      </tr>)}</tbody></table></div>
    {!filtered.length ? <p role="status" className="p-10 text-center text-sm text-muted-foreground">{loading ? "Loading inventory…" : "No matching inventory."}</p> : <Pagination currentPage={current} totalPages={pages} totalItems={filtered.length} pageSize={size} itemsName="entities" onPageChange={setPage} pageSizeOptions={[25, 50, 100]} onPageSizeChange={next => { setSize(next); setPage(1); }}/>}
    <Drawer open={Boolean(record)} onOpenChange={open => { if (!open) setSelected(null); }}><DrawerContent style={{ width: "min(680px, 100vw)", maxWidth: "100vw" }}>{record ? <><div className="border-b border-border px-5 py-4 pr-12"><DrawerTitle>{record.detail.name}</DrawerTitle><DrawerDescription>{entityKind(record.detail.kind)}</DrawerDescription></div><dl className="grid grid-cols-[120px_1fr] gap-3 p-5 text-sm">{[["Status", entityStatus(record)], ["Host", record.detail.hostname], ["Platform", record.detail.platform], ["Source", record.detail.connector_type], ["Protection", record.protection?.state], ["Last seen", formatDateTime(record.last_seen)], ["Evidence", record.detail.basis]].filter(([, value]) => value).map(([label, value]) => <div key={label} className="contents"><dt className="text-muted-foreground">{label}</dt><dd className="break-words">{value}</dd></div>)}</dl>{onReview ? <div className="flex flex-wrap gap-2 border-t border-border p-5" aria-label="Review entity">
      {([...(estateReviewOptions(record).sanction ? [["sanction", "Sanction"], ["unsanction", "Unsanction"]] : []), ...(estateReviewOptions(record).clear ? [["clear_sanction", "Use source policy"]] : []), [record.flagged ? "clear_flag" : "flag", record.flagged ? "Remove flag" : "Flag for review"]] as [EstateReviewAction, string][]).map(([action, label]) => <button key={action} disabled={saving} onClick={() => void review(record, action)} className="rounded-lg border border-border px-3 py-2 text-xs hover:bg-muted disabled:opacity-50">{label}</button>)}
    </div> : null}{error ? <p role="alert" className="px-5 text-sm text-destructive">{error}</p> : null}</> : null}</DrawerContent></Drawer>
  </div>;
}
