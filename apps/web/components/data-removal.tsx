"use client";
import { useState } from "react";
import { AlertTriangle, Database, LoaderCircle, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { deleteTallyData, getDataInventory, previewTallyData, type DataInventory } from "../lib/tally";
import { formatDateTime } from "../lib/datetime";
import { DataCounts, DataDeletionDialog } from "./data-deletion-dialog";
import { SampleData } from "./sample-data";

const scopes = [
  ["ai_logs", "Retained AI logs", "AI telemetry in ClickHouse; inventory is preserved"],
  ["inventory", "AI estate inventory", "Discovered agents, models and relationships"],
  ["findings", "Findings, endpoints, destinations, and users", "Unique AI usage and its actionable context"],
  ["connector_history", "Connector history", "Run history and ingestion receipts"],
  ["connectors", "Connector configurations", "Configured connector instances and schedules"],
  ["scanner_history", "Native Scanner history", "Authorized scan jobs and results"],
  ["audit_logs", "Audit logs", "Administrative and operational audit entries"],
  ["registry_sanctions", "Registry sanctions & inventory reviews", "Restore provider/model defaults and clear inventory sanction decisions and review flags"],
] as const;

type Target = { scopes: string[]; before: string | null };
export function DataRemoval({ initialInventory }: { initialInventory: DataInventory | null }) {
  const [inventory, setInventory] = useState(initialInventory);
  const [selected, setSelected] = useState<string[]>([]);
  const [before, setBefore] = useState("");
  const [preview, setPreview] = useState<DataInventory | null>(null);
  const [confirmation, setConfirmation] = useState<{ mode: "selected" | "all"; target: Target; counts: DataInventory } | null>(null);
  const [pending, setPending] = useState<"preview" | "delete" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [revision, setRevision] = useState(0);
  const target = (): Target => ({ scopes: selected, before: before ? new Date(before).toISOString() : null });
  function invalidate() { setPreview(null); setMessage(""); setError(null); }
  function choose(scope: string) {
    setSelected(old => old.includes(scope) ? old.filter(key => key !== scope) : [...old, scope]); invalidate();
  }
  async function runPreview(mode?: "selected" | "all") {
    setPending("preview"); setError(null); setMessage("");
    const snapshot: Target = mode === "all" ? { scopes: ["all"], before: null } : target();
    const result = await previewTallyData(snapshot); setPending(null);
    if (!result.ok) { setError(result.error); return; }
    setPreview(result.data);
    if (mode) setConfirmation({ mode, target: snapshot, counts: result.data });
  }
  async function removeData() {
    if (!confirmation) return;
    setPending("delete"); setError(null);
    const result = await deleteTallyData({ ...confirmation.target, confirmation: "DELETE SELECTED DATA" }); setPending(null);
    if (!result.ok) { setError(result.error); return; }
    setInventory(result.data); setConfirmation(null); setPreview(null); setSelected([]); setBefore("");
    setMessage("The selected Tally data was permanently removed."); setRevision(old => old + 1);
  }
  async function refreshInventory() { setInventory(await getDataInventory()); invalidate(); }
  return <div className="space-y-6">
    <SampleData revision={revision} onChanged={() => void refreshInventory()} />
    <section className="space-y-4" aria-label="Tally data deletion">
      <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">Data deletion</h2>
        <p className="mt-1 text-sm text-muted-foreground">Build a deletion target, preview its impact, then confirm.</p></div>
        <Button variant="destructive" disabled={pending !== null} onClick={() => void runPreview("all")}><Trash2 className="size-4" />Delete All…</Button>
      </div>
      <Card className="gap-0 border-amber-200 bg-amber-50/60 p-4 dark:border-amber-900 dark:bg-amber-950/20"><p className="flex items-start gap-2 text-sm text-amber-900 dark:text-amber-200">
        <AlertTriangle className="mt-0.5 size-4 shrink-0" />Deletion is permanent. The installation identity, user accounts, and built-in AI catalog are preserved. Connected sources may send new data after deletion.</p></Card>
      <Card className="gap-0 p-5"><h3 className="font-semibold">Build deletion target</h3><p className="mt-1 text-xs text-muted-foreground">Select one or more categories. The optional time limit applies to records within those categories.</p>
        <fieldset disabled={pending !== null} className="mt-4 space-y-4"><legend className="sr-only">Data categories</legend>
          <div className="grid gap-2 sm:grid-cols-2">{scopes.map(([key, label, detail]) => <label key={key} className="flex cursor-pointer items-start gap-3 rounded-lg border border-border p-3 hover:bg-muted/25">
            <input type="checkbox" checked={selected.includes(key)} onChange={() => choose(key)} className="mt-0.5 size-4 accent-[var(--primary)]" /><span><span className="block text-sm font-medium">{label}</span><span className="mt-1 block text-xs leading-relaxed text-muted-foreground">{detail}</span></span>
          </label>)}</div>
          <label className="block max-w-sm text-xs font-medium">Delete records older than<Input type="datetime-local" value={before} onChange={e => { setBefore(e.target.value); invalidate(); }} className="mt-2" /></label>
          <p className="text-xs text-muted-foreground">Connector configurations and provider/model sanction resets apply across all time. Deleting connectors also removes their run history and ingestion receipts.</p>
        </fieldset>
      </Card>
      <Card className="gap-0 p-5"><h3 className="text-sm font-semibold">Current target</h3><div className="mt-3 flex flex-wrap gap-2">
        {selected.length ? scopes.filter(([key]) => selected.includes(key)).map(([key, label]) => <span key={key} className="rounded-md border border-border bg-muted/40 px-2 py-1 text-xs">{label}</span>) : <p className="text-sm text-muted-foreground">No categories selected.</p>}
        {before ? <span className="rounded-md border border-border px-2 py-1 text-xs">Before {formatDateTime(before)}</span> : null}
      </div></Card>
      {preview ? <Card className="gap-0 p-5"><h3 className="mb-4 text-sm font-semibold">Matches to delete</h3><DataCounts counts={preview} /></Card> : null}
      {message ? <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/25 dark:text-emerald-200">{message}</p> : null}
      {error && !confirmation ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
      <div className="flex flex-wrap items-center gap-3"><Button variant="outline" disabled={!selected.length || pending !== null} onClick={() => void runPreview()}>
        {pending === "preview" ? <LoaderCircle className="size-4 animate-spin" /> : <Database className="size-4" />}Preview</Button>
        <Button variant="destructive" disabled={!selected.length || pending !== null} onClick={() => void runPreview("selected")}><Trash2 className="size-4" />Delete…</Button>
        {!selected.length ? <span className="text-xs text-muted-foreground">Select a category to enable deletion.</span> : null}
      </div>
      <details className="rounded-xl border border-border bg-card p-5"><summary className="cursor-pointer text-sm font-semibold">Stored data</summary>
        <div className="mt-4">{inventory ? <DataCounts counts={inventory} /> : <p className="text-sm text-muted-foreground">The data inventory is unavailable.</p>}</div>
      </details>
      {confirmation ? <DataDeletionDialog key={confirmation.mode} mode={confirmation.mode} counts={confirmation.counts} pending={pending === "delete"} error={error}
        onClose={() => { setConfirmation(null); setError(null); setPreview(null); }} onConfirm={() => void removeData()} /> : null}
    </section>
  </div>;
}
