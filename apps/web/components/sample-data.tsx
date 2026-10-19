"use client";
import { useEffect, useState } from "react";
import { ArrowRight, Database, LoaderCircle, Sparkles, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { addSampleData, getSampleData, removeSampleData, type SampleDataStatus } from "../lib/tally";
import { DataDeletionDialog } from "./data-deletion-dialog";

export function SampleData({ empty = false, revision = 0, onChanged }: { empty?: boolean; revision?: number; onChanged: () => void }) {
  const [status, setStatus] = useState<SampleDataStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [pending, setPending] = useState<"add" | "preview" | "remove" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState("");
  const [confirm, setConfirm] = useState<SampleDataStatus | null>(null);
  useEffect(() => {
    let cancelled = false;
    void getSampleData().then(data => { if (!cancelled) { setStatus(data); setLoading(false); } });
    return () => { cancelled = true; };
  }, [revision]);
  async function add() {
    setPending("add"); setError(null); setMessage("");
    const result = await addSampleData(); setPending(null);
    if (!result.ok) { setError(result.error); return; }
    setStatus(result.data); setMessage("Evaluation workspace added. Explore the overview, connectors, registry, and audit history."); onChanged();
  }
  async function preview() {
    setPending("preview"); setError(null);
    const next = await getSampleData(); setPending(null);
    if (!next) { setError("Could not preview evaluation data. Try again."); return; }
    setStatus(next);
    if (next.present) setConfirm(next);
  }
  async function remove() {
    setPending("remove"); setError(null);
    const result = await removeSampleData(); setPending(null);
    if (!result.ok) { setError(result.error); return; }
    setStatus(result.data); setConfirm(null); setMessage("Evaluation data removed. Your other data is preserved."); onChanged();
  }
  return <Card className={`gap-0 p-5 ${empty ? "border-primary/25 bg-primary/5 sm:p-8" : ""}`} aria-label="Evaluation workspace">
    <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
      <div className="max-w-2xl space-y-2"><div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-primary"><Sparkles className="size-4" />Evaluation workspace</div>
        <h2 className="text-lg font-semibold">{empty ? "See your AI estate come to life" : "Explore Tally with evaluation data"}</h2>
        <p className="text-sm leading-relaxed text-muted-foreground">Explore an enterprise AI estate with OpenAI, Anthropic, Gemini, Amazon Bedrock, Ollama, and more. Follow people, applications, and workloads across every connector and category.</p>
        <p className="text-xs leading-relaxed text-muted-foreground">Real product names and realistic activity, generated for evaluation. No credentials, live connections, or network scans are required. Remove this dataset at any time in Settings.</p>
        {status?.present ? <p className="text-xs font-medium">{status.connector_types.length} connector types · {status.categories.length} categories · {status.observation_kinds.length} event types
          {status.state !== "ready" ? " · Partially applied — finish adding or remove the evaluation workspace." : " · Evaluation workspace installed"}</p> : null}
      </div>
      <div className="flex shrink-0 flex-wrap gap-2 sm:flex-col">
        <Button onClick={() => void add()} disabled={pending !== null || loading || status?.state === "removing"}>
          {pending === "add" ? <LoaderCircle className="size-4 animate-spin" /> : empty ? <ArrowRight className="size-4" /> : <Database className="size-4" />}
          {pending === "add" ? "Adding evaluation data…" : status?.present ? "Restore evaluation data" : "Add evaluation data"}
        </Button>
        {!empty && status?.present ? <Button variant="destructive" onClick={() => void preview()} disabled={pending !== null}>
          {pending === "preview" ? <LoaderCircle className="size-4 animate-spin" /> : <Trash2 className="size-4" />}Remove evaluation data…</Button> : null}
      </div>
    </div>
    {!loading && !status ? <p role="alert" className="mt-3 text-sm text-destructive">Evaluation workspace status is unavailable. You can retry adding it safely.</p> : null}
    {error && !confirm ? <p role="alert" className="mt-3 text-sm text-destructive">{error}</p> : null}
    {message ? <p role="status" className="mt-3 text-sm text-emerald-700 dark:text-emerald-300">{message}</p> : null}
    {confirm ? <DataDeletionDialog mode="sample" counts={confirm.counts} pending={pending === "remove"} error={error} onClose={() => { setConfirm(null); setError(null); }} onConfirm={() => void remove()} /> : null}
  </Card>;
}
