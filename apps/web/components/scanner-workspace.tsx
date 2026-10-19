"use client";

import {
  Ban,
  Check,
  ChevronRight,
  CircleStop,
  Gauge,
  Info,
  LoaderCircle,
  Network,
  Play,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";

import { Panel, StatusPill } from "./page-kit";
import { tallyFetch, type ScanJob, type ScanPreview } from "../lib/tally";
const terminal = new Set(["completed", "cancelled", "failed"]);

export function ScannerWorkspace({ initialJobs }: { initialJobs: ScanJob[] }) {
  const [mode, setMode] = useState<"local" | "explicit">("local");
  const [targetText, setTargetText] = useState("127.0.0.1");
  const [exclusionText, setExclusionText] = useState("");
  const [portsText, setPortsText] = useState("80,443,3000,4000,7860,8000,8001,8002,8080,8081,11434");
  const [preview, setPreview] = useState<ScanPreview | null>(null);
  const [job, setJob] = useState<ScanJob | null>(initialJobs[0] ?? null);
  const [authorized, setAuthorized] = useState(false);
  const [countdown, setCountdown] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const active = job && !terminal.has(job.status);
  useEffect(() => {
    if (!active || !job) return;
    const timer = window.setInterval(async () => {
      const response = await tallyFetch(`/scans/${job.scan_id}`, { cache: "no-store" });
      if (response.ok) setJob((await response.json()) as ScanJob);
    }, 700);
    return () => window.clearInterval(timer);
  }, [active, job]);

  const plan = preview?.plan;
  const openResults = useMemo(() => job?.results.filter((item) => item.state === "open") ?? [], [job]);

  async function reviewScope() {
    setBusy(true);
    setMessage(null);
    setAuthorized(false);
    setCountdown(null);
    try {
      const response = await tallyFetch("/scans/preview", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          targets: mode === "local" ? [] : splitValues(targetText),
          exclusions: splitValues(exclusionText),
          ports: splitValues(portsText).map(Number).filter(Number.isInteger),
          max_hosts: 1024,
          allow_public: false,
          public_target_authorization: false,
        }),
      });
      if (!response.ok) throw new Error(await problemMessage(response));
      setPreview((await response.json()) as ScanPreview);
      setJob(null);
    } catch (error) {
      setPreview(null);
      setMessage(error instanceof Error ? error.message : "Scope preview failed.");
    } finally {
      setBusy(false);
    }
  }

  const startScan = useCallback(async () => {
    if (!plan || !authorized) return;
    setBusy(true);
    setMessage(null);
    try {
      const response = await tallyFetch("/scans", {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({
          plan,
          confirm_scope_digest: plan.scope_digest,
          authorized_to_scan: true,
          execution_policy: { concurrency: 64, connect_timeout_millis: 1500 },
        }),
      });
      if (!response.ok) throw new Error(await problemMessage(response));
      setJob((await response.json()) as ScanJob);
      setMessage("Scan authorized. Tally will probe only the reviewed addresses and ports.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Scan start failed.");
    } finally {
      setBusy(false);
    }
  }, [authorized, plan]);

  useEffect(() => {
    if (countdown === null) return;
    const timer = window.setTimeout(() => {
      if (countdown <= 1) {
        setCountdown(null);
        void startScan();
      } else {
        setCountdown(countdown - 1);
      }
    }, 1_000);
    return () => window.clearTimeout(timer);
  }, [countdown, startScan]);

  async function cancelScan() {
    if (!job) return;
    setBusy(true);
    try {
      const response = await tallyFetch(`/scans/${job.scan_id}/cancel`, { method: "POST" });
      if (!response.ok) throw new Error(await problemMessage(response));
      setJob((await response.json()) as ScanJob);
      setMessage("Cancellation requested. No additional probes will be scheduled.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Cancellation failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
        <div className="space-y-5">
          <Panel title="1 · Choose scope" description="Local discovery inspects active physical interfaces; explicit targets accept only exact IPs and CIDRs">
            <div className="space-y-4 p-5">
              <div className="grid grid-cols-2 gap-2 rounded-xl bg-muted p-1">
                {([ ["local", "This Mac's network"], ["explicit", "Explicit targets"] ] as const).map(([value, label]) => (
                  <button key={value} type="button" onClick={() => { setMode(value); setPreview(null); setCountdown(null); }} className={`rounded-lg px-3 py-2 text-xs font-bold ${mode === value ? "bg-card text-foreground shadow-sm" : "text-muted-foreground"}`}>{label}</button>
                ))}
              </div>
              {mode === "explicit" ? <Field label="Targets" value={targetText} onChange={setTargetText} placeholder="10.20.0.0/24, 192.168.1.15" /> : <p className="rounded-xl border border-border bg-muted/25 p-4 text-xs leading-relaxed text-muted-foreground">Tally will enumerate directly connected private networks when you click review. VPN, tunnel, container, loopback, public, link-local, multicast, and oversized ranges are excluded automatically.</p>}
              <Field label="Exclusions" value={exclusionText} onChange={setExclusionText} placeholder="10.20.0.1, 10.20.0.128/25" />
              <Field label="Allowlisted ports" value={portsText} onChange={setPortsText} placeholder="443,8000,11434" />
              <button type="button" onClick={reviewScope} disabled={busy || Boolean(active)} className="inline-flex h-10 items-center gap-2 rounded-lg bg-primary px-4 text-xs font-bold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">
                {busy ? <LoaderCircle className="size-4 animate-spin" /> : <ChevronRight className="size-4" />} Review exact scope
              </button>
            </div>
          </Panel>

          {preview ? <Panel title="2 · Exact immutable plan" description="Preview sent no traffic. This digest binds every target, port, and public-scope control.">
            <div className="divide-y divide-border">
              {preview.requested_targets.map((target) => <div key={target} className="flex items-center justify-between gap-4 px-5 py-4"><div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary"><Network className="size-4" /></span><div><p className="font-mono text-sm font-bold">{target}</p><p className="mt-0.5 text-xs text-muted-foreground">{preview.discovered_local_scope ? "Directly connected private scope" : "Explicitly provided target"}</p></div></div><StatusPill tone="good">Included</StatusPill></div>)}
            </div>
            <div className="grid gap-3 border-t border-border p-5 sm:grid-cols-3">
              <Metric label="Hosts" value={plan?.host_count ?? 0} />
              <Metric label="Ports" value={plan?.ports.length ?? 0} />
              <Metric label="Maximum probes" value={plan?.probe_count ?? 0} />
            </div>
            <div className="border-t border-border bg-muted/20 p-4"><p className="break-all font-mono text-[10px] text-muted-foreground">SHA-256 {plan?.scope_digest}</p></div>
          </Panel> : null}

          {job ? <Panel title="Scan run" description="Durable authorization receipt, reachability, and benign fingerprint evidence">
            <div className="grid gap-3 p-5 sm:grid-cols-3 lg:grid-cols-6"><Metric label="Status" value={pretty(job.status)} /><Metric label="Completed" value={`${job.completed_probes}/${job.planned_probes}`} /><Metric label="Open ports" value={job.open_port_count} /><Metric label="Fingerprints" value={`${job.fingerprint_match_count}/${job.fingerprint_attempt_count}`} /><Metric label="Systems" value={job.resolved_system_count} /><Metric label="Content stored" value="No" /></div>
            {openResults.length ? <div className="border-t border-border"><div className="px-5 py-3 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Reachable endpoints</div>{openResults.map((result) => <div key={`${result.address}:${result.port}`} className="flex items-center justify-between border-t border-border px-5 py-3 text-xs"><span className="font-mono font-bold">{result.address}:{result.port}</span><StatusPill tone="good">Open · {result.duration_millis} ms</StatusPill></div>)}</div> : null}
            <div className="flex flex-wrap items-center gap-3 border-t border-border p-4">{active ? <button type="button" onClick={cancelScan} disabled={busy} className="inline-flex h-9 items-center gap-2 rounded-lg border border-red-300 bg-red-50 px-3 text-xs font-bold text-red-700 disabled:opacity-50 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"><CircleStop className="size-4" />Cancel safely</button> : <button type="button" onClick={() => { setPreview(null); setJob(null); setAuthorized(false); setCountdown(null); setMessage(null); }} className="inline-flex h-9 items-center gap-2 rounded-lg border border-border bg-card px-3 text-xs font-bold"><RotateCcw className="size-4" />New scan</button>}<span className="font-mono text-[10px] text-muted-foreground">receipt {job.scan_id}</span></div>
          </Panel> : null}
        </div>

        <div className="space-y-5">
          <Panel title="Safe execution limits"><dl className="space-y-4 p-5 text-sm">{[["Concurrency", "64 connections"], ["Connect timeout", "1,500 ms"], ["Host ceiling", "1,024 per run"], ["Scope receipt", "SHA-256 bound"], ["Redirects / auth", "Never"]].map(([term,value]) => <div key={term} className="flex items-center justify-between gap-4"><dt className="text-muted-foreground">{term}</dt><dd className="font-mono text-xs font-bold">{value}</dd></div>)}</dl></Panel>
          {preview && !job ? <Panel title="3 · Authorization"><div className="space-y-4 p-5"><label className="flex items-start gap-3 text-xs leading-relaxed"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} disabled={countdown !== null} className="mt-0.5 size-4 accent-[var(--primary)]" /><span>I confirm I am authorized to scan every address in this exact reviewed plan.</span></label>{countdown === null ? <button type="button" onClick={() => setCountdown(10)} disabled={!authorized || busy} className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-primary px-4 text-xs font-bold text-primary-foreground disabled:cursor-not-allowed disabled:opacity-50">{busy ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}Start 10-second countdown</button> : <div className="space-y-2"><div className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-center text-xs font-bold text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200">Scan begins in {countdown} seconds</div><button type="button" onClick={() => setCountdown(null)} className="inline-flex h-9 w-full items-center justify-center gap-2 rounded-lg border border-border bg-card px-3 text-xs font-bold"><CircleStop className="size-4" />Cancel countdown</button></div>}</div></Panel> : null}
          <section className="rounded-xl border border-emerald-300/60 bg-emerald-50 p-5 dark:border-emerald-900 dark:bg-emerald-950/30"><ShieldCheck className="size-6 text-emerald-600 dark:text-emerald-400" /><h2 className="mt-3 text-sm font-bold">Safety contract</h2><ul className="mt-3 space-y-2 text-xs leading-relaxed text-emerald-950 dark:text-emerald-100">{["No credentials, exploits, prompts, or inference", "No banners, response bodies, or model output", "Hard host, port, concurrency, and timeout limits", "Cancellation stops new probes and drains in flight", "Append-only authorization and outcome audit"].map((item) => <li key={item} className="flex gap-2"><Check className="mt-0.5 size-3.5 shrink-0" />{item}</li>)}</ul></section>
          <section className="rounded-xl border border-red-300/60 bg-red-50 p-5 dark:border-red-900 dark:bg-red-950/30"><div className="flex gap-3"><Ban className="mt-0.5 size-5 shrink-0 text-red-600" /><div><h2 className="text-sm font-bold">Automatic refusals</h2><p className="mt-1 text-xs leading-relaxed text-red-900 dark:text-red-100">Hostnames, public ranges without dual controls, cloud metadata, multicast, broadcast, and non-allowlisted ports fail before a probe is scheduled.</p></div></div></section>
        </div>
      </div>
      {message ? <div role="status" className="flex items-start gap-3 rounded-xl border border-border bg-card p-4 text-xs text-muted-foreground"><Info className="mt-0.5 size-4 shrink-0 text-primary" /><p>{message}</p></div> : null}
      <div className="flex items-start gap-3 rounded-xl border border-border bg-card p-4 text-xs text-muted-foreground"><Gauge className="mt-0.5 size-4 shrink-0 text-primary" /><p><span className="font-bold text-foreground">Evidence boundary:</span> reachability alone never becomes an AI-system claim. Tally runs only the bounded fingerprint contracts shown in Registry; a distinctive match becomes immutable evidence and can resolve a runtime.</p></div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder: string }) {
  return <label className="block"><span className="mb-1.5 block text-xs font-bold">{label}</span><input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} className="h-10 w-full rounded-lg border border-border bg-background px-3 font-mono text-xs outline-none focus:border-primary" /></label>;
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return <div className="rounded-xl border border-border bg-background/50 p-4"><p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">{label}</p><p className="mt-2 font-mono text-sm font-bold">{value}</p></div>;
}

function splitValues(value: string) { return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean); }
function pretty(value: string) { return value.replaceAll("_", " ").replace(/^./, (letter) => letter.toUpperCase()); }
async function problemMessage(response: Response) { const body = await response.json().catch(() => null) as { title?: string } | null; return body?.title ?? `Tally returned ${response.status}.`; }
