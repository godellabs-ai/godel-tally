"use client";
import { useState } from "react";
import { LoaderCircle, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import type { DataInventory } from "../lib/tally";

const labels: Record<keyof DataInventory, string> = {
  ai_logs: "AI logs", inventory_entities: "Inventory entities", findings: "Findings", endpoint_hosts: "Endpoint hosts",
  destination_hosts: "Destinations", endpoint_users: "Users", connectors: "Connectors", connector_runs: "Connector runs",
  ingestion_receipts: "Ingestion receipts", scanner_runs: "Scanner runs", audit_events: "Audit events", registry_sanctions: "Sanctions & reviews",
};
export const dataTotal = (counts: DataInventory) => Object.values(counts).reduce((sum, n) => sum + n, 0);
export function DataCounts({ counts }: { counts: DataInventory }) {
  return <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-4">{Object.entries(labels).map(([key, label]) => <div key={key}>
    <dd className="text-2xl font-bold tabular-nums">{(counts[key as keyof DataInventory] ?? 0).toLocaleString()}</dd>
    <dt className="mt-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">{label}</dt>
  </div>)}</dl>;
}

/** Shared by standalone Tally and the Gate host. Mirrors Gate's typed confirmation flow. */
export function DataDeletionDialog({ mode, counts, pending, error, onClose, onConfirm }: {
  mode: "selected" | "all" | "sample"; counts: DataInventory; pending: boolean; error?: string | null;
  onClose: () => void; onConfirm: () => void;
}) {
  const [text, setText] = useState("");
  const phrase = mode === "all" ? "delete all" : mode === "sample" ? "delete evaluation data" : "delete";
  const ready = text === phrase;
  return <Dialog open onOpenChange={open => { if (!open && !pending) onClose(); }}><DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
    <DialogHeader><DialogTitle>{mode === "all" ? "Confirm deletion of all data" : mode === "sample" ? "Confirm evaluation data removal" : "Confirm permanent deletion"}</DialogTitle>
      <DialogDescription>This will permanently remove {dataTotal(counts).toLocaleString()} records and decisions. {mode === "sample" ? "Only records owned by the evaluation workspace are selected. Your other data is preserved." : "This cannot be undone. New activity may arrive after this preview."}</DialogDescription>
    </DialogHeader>
    <DataCounts counts={counts} />
    <label className="space-y-2 text-sm font-medium">{`Type "${phrase}" to confirm`}<Input autoFocus value={text} onChange={e => setText(e.target.value)}
      onKeyDown={e => { if (e.key === "Enter" && ready && !pending) onConfirm(); }} placeholder={phrase} autoComplete="off" disabled={pending} className="mt-2 font-mono" /></label>
    {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
    <DialogFooter><Button variant="ghost" onClick={onClose} disabled={pending}>Cancel</Button><Button variant="destructive" onClick={onConfirm} disabled={!ready || pending}>
      {pending ? <LoaderCircle className="size-4 animate-spin" /> : <Trash2 className="size-4" />}Delete permanently
    </Button></DialogFooter>
  </DialogContent></Dialog>;
}
