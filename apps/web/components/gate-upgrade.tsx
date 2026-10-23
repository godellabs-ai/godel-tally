"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Loader2 } from "lucide-react";
import { upgradeApi, isTransientUpgradeError } from "@/lib/upgrade";
import { formatDateTime } from "@/lib/datetime";
import { authFetch } from "@/lib/session";

type UpgradeStatus = {
  available?: boolean; unavailable_reason?: string | null;
  status: string; version: string | null; temporary_url: string | null; requested_final_url: string | null; final_url: string | null;
  expires_at: string | null; verification: string | null; busy: boolean;
  suggested_tls_cert: string | null; suggested_tls_key: string | null; suggested_gate_dir: string | null;
  requested_tls_cert: string | null; requested_tls_key: string | null; requested_gate_dir: string | null;
  failure_reason: string | null;
  migration_warning?: string | null;
  cutover_retryable: boolean;
  cutover_stage: string | null;
  attempt_log: { name: string; content: string; truncated: boolean } | null;
  progress: { at: string; message: string }[];
};
type UpgradePreview = {
  temporary_url: string; version: string; installer_sha256: string;
  expires_at: string | null; digest: string; effects: string[];
};
const field = "mt-2 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm";
const button = "rounded-lg border border-border px-3 py-2 text-xs font-semibold disabled:opacity-50";
const primary = `${button} border-primary bg-primary text-primary-foreground`;
const upgradeStageLabels: Record<string, string> = {
  not_started: "Let’s get Gödel Gate ready",
  preflight: "Checking your installation",
  staging: "Preparing Gödel Gate",
  copying: "Transferring your Tally data",
  verifying: "Checking your Gate installation",
  ready_for_cutover: "Ready for your review",
  cutting_over: "Switching to Gödel Gate",
  gate_live: "Gödel Gate is live",
  failed: "Your upgrade needs attention",
  cutover_failed: "The switch to Gate needs attention",
  cancelled: "Upgrade cancelled · Tally resumed",
};
const upgradeMilestones = [
  { label: "Installer verified", signal: "Verified Gate Console installer" },
  { label: "Gate import database ready", signal: "Gate import database is healthy" },
  { label: "Tally backup saved", signal: "Tally database backup saved and checksummed" },
  { label: "Tally data restored", signal: "Tally data restored to Gate PostgreSQL" },
  { label: "Gate services started", signal: "Gate services started on review HTTPS port" },
  { label: "Copied data and Gate verified", signal: "Gate health and Tally record counts verified" },
  { label: "Gate worker and API switched", signal: "Gate worker and API switched to the final URL" },
  { label: "Gate HTTPS verified", signal: "Gate final HTTPS endpoint verified" },
  { label: "Tally stopped; volume retained", signal: "Tally containers stopped; volume retained" },
] as const;

function completedMilestones(status: UpgradeStatus) {
  const floor: Record<string, number> = {
    staging: 1, copying: 2, verifying: 5, ready_for_cutover: 6,
    cutting_over: 6, cutover_failed: 6, gate_live: upgradeMilestones.length,
  };
  const fromEvents = upgradeMilestones.reduce((count, milestone, index) =>
    status.progress?.some(entry => entry.message.startsWith(milestone.signal)) ? index + 1 : count, 0);
  return Math.max(floor[status.status] ?? 0, fromEvents);
}

function UpgradeProgress({ status, starting = false }: { status: UpgradeStatus | null; starting?: boolean }) {
  const completed = status ? completedMilestones(status) : 0;
  const phase = status?.status ?? "starting";
  const running = starting || ["preflight", "staging", "copying", "verifying", "cutting_over"].includes(phase);
  const state = upgradeStageLabels[phase] ?? (running ? "Getting your upgrade ready" : "Checking upgrade status");
  return <section className="rounded-xl border border-primary/20 bg-background/80 p-3.5" aria-label="Gate upgrade progress">
    <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-semibold">
      <span className="flex items-center gap-2">{running && <Loader2 className="size-3.5 animate-spin text-primary" />}{state}</span>
      <span>{completed} of {upgradeMilestones.length} checkpoints verified</span>
    </div>
    <div role="progressbar" aria-label="Verified upgrade checkpoints" aria-valuemin={0} aria-valuemax={upgradeMilestones.length} aria-valuenow={completed} aria-valuetext={`${completed} of ${upgradeMilestones.length} checkpoints verified`} className="mt-2 h-2.5 overflow-hidden rounded-full bg-muted">
      <div className="h-full rounded-full bg-primary transition-[width] duration-500" style={{ width: `${completed / upgradeMilestones.length * 100}%` }} />
    </div>
    <p className="mt-2 text-xs text-muted-foreground">{phase === "ready_for_cutover" ? "Sign in to Gate and explore your data. You’ll approve the switch when you’re ready." : phase === "gate_live" ? "Your upgrade is complete. Sign in to Gödel Gate with your Tally account." : running ? "We’ll update your progress as each check completes. This may take a few minutes." : "Your completed checks are shown here."}</p>
    {running && completed < upgradeMilestones.length && <p className="mt-1 text-[11px] text-muted-foreground">Next checkpoint: {upgradeMilestones[completed].label}. Progress reflects completed checks, not elapsed time.</p>}
  </section>;
}

function defaultFinalUrl() {
  if (typeof window === "undefined") return "";
  const current = new URL(window.location.href);
  current.protocol = "https:";
  current.port = "";
  return current.origin;
}

export function GateUpgrade() {
  const [isAdmin, setIsAdmin] = useState<boolean | null>(null);
  const [hostReady, setHostReady] = useState(false);
  const [finalUrl, setFinalUrl] = useState(defaultFinalUrl);
  const [tlsCert, setTlsCert] = useState("");
  const [tlsKey, setTlsKey] = useState("");
  const [gateDir, setGateDir] = useState("");
  const [registrationKey, setRegistrationKey] = useState("");
  const [gateReviewed, setGateReviewed] = useState(false);
  const [review, setReview] = useState<UpgradePreview | null>(null);
  const [status, setStatus] = useState<UpgradeStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [prepareStarted, setPrepareStarted] = useState(false);
  const [error, setError] = useState("");
  const [workingLabel, setWorkingLabel] = useState("");
  const suggestedPathsLoaded = useRef(false);
  const portalState = useRef("");
  const openedReview = useRef("");
  const reviewWindow = useRef<Window | null>(null);
  const gateFinalChecksPassed = status?.cutover_stage === "retiring_tally" && Boolean(status.final_url);

  useEffect(() => {
    let active = true;
    void authFetch("me", { cache: "no-store" })
      .then(response => response.ok ? response.json() : null).catch(() => null)
      .then(body => { if (active) setIsAdmin(body?.user?.role === "admin"); });
    return () => { active = false; };
  }, []);
  const refresh = useCallback(async () => {
    if (!isAdmin) return;
    try {
      const next = await upgradeApi<UpgradeStatus>("status");
      setStatus(next);
      setHostReady(true);
      if (!suggestedPathsLoaded.current) {
        suggestedPathsLoaded.current = true;
        if (next.requested_final_url) setFinalUrl(next.requested_final_url);
        if (next.requested_tls_cert || next.suggested_tls_cert) setTlsCert(current => current || next.requested_tls_cert || next.suggested_tls_cert || "");
        if (next.requested_tls_key || next.suggested_tls_key) setTlsKey(current => current || next.requested_tls_key || next.suggested_tls_key || "");
        if (next.requested_gate_dir || next.suggested_gate_dir) setGateDir(current => current || next.requested_gate_dir || next.suggested_gate_dir || "");
      }
    }
    // The 3-second poll retries dropped connections; report only lasting failures.
    catch (cause) {
      setHostReady(false);
      if (!isTransientUpgradeError(cause)) setError(cause instanceof Error ? cause.message : "Could not read upgrade status.");
    }
  }, [isAdmin]);
  useEffect(() => {
    if (!isAdmin) return;
    const first = window.setTimeout(() => void refresh(), 0);
    const interval = window.setInterval(() => void refresh(), 3000);
    return () => { window.clearTimeout(first); window.clearInterval(interval); };
  }, [refresh, isAdmin]);
  useEffect(() => {
    function receiveKey(event: MessageEvent) {
      if (event.origin !== "https://portal.godel-labs.ai" || event.data?.type !== "godel-tally-registration-key" || event.data?.state !== portalState.current || !/^gg_[A-Za-z0-9_-]{12,256}$/.test(event.data?.key ?? "")) return;
      setRegistrationKey(event.data.key);
      setReview(null);
      setError("");
    }
    window.addEventListener("message", receiveKey);
    return () => window.removeEventListener("message", receiveKey);
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => {
      const hash = window.location.hash;
      if (!hash.startsWith("#gate-upgrade-key=")) return;
      let key = "";
      try { key = decodeURIComponent(hash.slice("#gate-upgrade-key=".length)); }
      catch { setError("The portal return link was invalid."); }
      window.history.replaceState(window.history.state, "", window.location.pathname + window.location.search);
      if (!/^gg_[A-Za-z0-9_-]{12,256}$/.test(key)) { setError("The portal did not return a valid registration key."); return; }
      setRegistrationKey(key);
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);
  useEffect(() => {
    if (status?.status !== "ready_for_cutover" || !status.temporary_url || openedReview.current === status.temporary_url) return;
    openedReview.current = status.temporary_url;
    if (reviewWindow.current && !reviewWindow.current.closed) reviewWindow.current.location.href = status.temporary_url;
    else window.open(status.temporary_url, "_blank");
  }, [status?.status, status?.temporary_url]);
  useEffect(() => {
    if (status?.status === "failed" && reviewWindow.current && !reviewWindow.current.closed) reviewWindow.current.close();
  }, [status?.status]);
  const config = { final_url: finalUrl.trim(), gate_dir: gateDir.trim(), registration_key: registrationKey.trim() };
  function reserveReviewWindow() {
    const next = window.open("", "_blank");
    if (!next) return;
    reviewWindow.current = next;
    next.document.title = "Getting Gödel Gate ready";
    next.document.body.textContent = "We’re preparing Gödel Gate for your review. You can follow progress in your Tally tab. This window will open Gate when the checks are complete.";
    next.blur();
    window.focus();
  }
  async function openPortal() {
    const portalWindow = window.open("", "_blank");
    if (!portalWindow) { setError("Allow pop-ups to open the registration portal."); return; }
    portalWindow.document.title = "Opening Gödel Gate registration";
    portalWindow.document.body.textContent = "Opening registration…";
    try {
      const response = await authFetch("me", { cache: "no-store" }).catch(() => null);
      if (!response?.ok) throw new Error("Could not read your account. Sign in again and retry.");
      const body = await response.json() as { user: { email: string; first_name: string | null; last_name: string | null } };
      const state = crypto.randomUUID();
      portalState.current = state;
      const account = new URL("https://portal.godel-labs.ai/account");
      account.searchParams.set("source", "godel-tally");
      account.searchParams.set("tally_origin", window.location.origin);
      account.searchParams.set("state", state);
      const signin = new URL("https://portal.godel-labs.ai/signin");
      signin.searchParams.set("mode", "register");
      signin.searchParams.set("source", "godel-tally");
      signin.searchParams.set("redirect", account.pathname + account.search);
      if (body.user.email) signin.searchParams.set("email", body.user.email);
      if (body.user.first_name?.trim()) signin.searchParams.set("first_name", body.user.first_name.trim());
      if (body.user.last_name?.trim()) signin.searchParams.set("last_name", body.user.last_name.trim());
      portalWindow.location.href = signin.toString();
    } catch (cause) { portalWindow.close(); setError(cause instanceof Error ? cause.message : "Could not open the registration portal."); }
  }
  async function preview() {
    if (busy || status?.busy || !hostReady) return;
    setBusy(true); setWorkingLabel("Checking your registration and preparing the installation details…"); setError(""); setReview(null);
    try { setReview(await upgradeApi<UpgradePreview>("preview", config)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not review upgrade."); }
    finally { setBusy(false); setWorkingLabel(""); }
  }
  async function prepare() {
    if (!review) return;
    setGateReviewed(false);
    reserveReviewWindow();
    setBusy(true); setWorkingLabel("Starting your Gate installation and data transfer…"); setError("");
    try {
      await upgradeApi("prepare", { ...config, version: review.version,
        installer_sha256: review.installer_sha256, digest: review.digest, approved: true });
      setRegistrationKey(""); setReview(null); setPrepareStarted(true); await refresh();
    } catch (cause) { reviewWindow.current?.close(); setError(cause instanceof Error ? cause.message : "Could not start upgrade."); }
    finally { setBusy(false); setWorkingLabel(""); }
  }
  async function cutover() {
    if (!finalUrl.trim()) { setError("Enter the final HTTPS URL for your Gate Console before switching."); return; }
    if (!tlsCert.trim() || !tlsKey.trim()) { setError("Enter readable host paths for the production certificate and private key before switching."); return; }
    setBusy(true); setWorkingLabel("Starting the switch to Gödel Gate…"); setError("");
    try { await upgradeApi("cutover", { final_url: finalUrl.trim(), tls_cert: tlsCert.trim(), tls_key: tlsKey.trim(), approved: true }); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not start cutover."); }
    finally { setBusy(false); setWorkingLabel(""); }
  }
  async function cancel() {
    setBusy(true); setWorkingLabel("Resuming Tally…"); setError("");
    try { await upgradeApi("cancel", { approved: true }); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not resume Tally."); }
    finally { setBusy(false); setWorkingLabel(""); }
  }
  async function reset() {
    setBusy(true); setWorkingLabel("Archiving the previous attempt…"); setError("");
    try { await upgradeApi("reset", {}); setRegistrationKey(""); setReview(null);
      setPrepareStarted(false); setGateReviewed(false);
      // Start from the defaults again; the next status read refills the suggested paths.
      setFinalUrl(defaultFinalUrl()); setGateDir(""); setTlsCert(""); setTlsKey("");
      suggestedPathsLoaded.current = false; await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : "Could not reset the upgrade."); }
    finally { setBusy(false); setWorkingLabel(""); }
  }
  async function retry() {
    if (!review) return;
    setGateReviewed(false);
    reserveReviewWindow();
    setBusy(true); setWorkingLabel("Archiving the failed attempt and starting Gate again…"); setError("");
    try {
      await upgradeApi("reset", {});
      await upgradeApi("prepare", { ...config, version: review.version,
        installer_sha256: review.installer_sha256, digest: review.digest, approved: true });
      setRegistrationKey(""); setReview(null); setPrepareStarted(true); await refresh();
    } catch (cause) { reviewWindow.current?.close(); setError(cause instanceof Error ? cause.message : "Could not retry the upgrade."); await refresh(); }
    finally { setBusy(false); setWorkingLabel(""); }
  }

  const started = Boolean(status && status.status !== "not_started");
  const running = Boolean(status && ["preflight", "staging", "copying", "verifying", "cutting_over"].includes(status.status));
  const locked = busy || Boolean(status?.busy);
  function changeDetails(update: () => void) { update(); setReview(null); setError(""); }
  const detailsForm = <form aria-label="Upgrade details" className="space-y-5" onSubmit={event => { event.preventDefault(); void preview(); }}>
    <fieldset disabled={locked} className="space-y-5 disabled:opacity-60">
      <label className="block text-sm font-semibold">Registration key
        <input required type="password" autoComplete="off" value={registrationKey} onChange={event => changeDetails(() => setRegistrationKey(event.target.value))} aria-label="Registration key" className={field} placeholder="gg_…" />
        <span className="mt-2 block text-xs font-normal text-muted-foreground">Get your key from <a href="https://portal.godel-labs.ai/account" target="_blank" rel="noopener noreferrer" className="text-primary underline">your portal account</a> or <button type="button" onClick={() => void openPortal()} className="text-primary underline">create an account</button>.</span>
      </label>
      <label className="block text-sm font-semibold">Final Gate Console URL
        <input required type="url" value={finalUrl} onChange={event => changeDetails(() => setFinalUrl(event.target.value))} className={field} placeholder="https://console.example.com" />
      </label>
      <label className="block text-sm font-semibold">Gate install directory
        <input required value={gateDir} onChange={event => changeDetails(() => setGateDir(event.target.value))} aria-label="Gate install directory" className={field} placeholder="/path/to/godel-gate" />
        <span className="mt-2 block text-xs font-normal text-muted-foreground">Use an empty directory on this host.{status?.status === "failed" ? " You can reuse the previous directory; partial installation files will be archived." : ""}</span>
      </label>
      {!review && <button type="submit" disabled={!hostReady || !registrationKey.trim() || !finalUrl.trim() || !gateDir.trim()} className={primary}>{busy ? "Reviewing…" : "Review upgrade"}</button>}
    </fieldset>
    {review && <section aria-label="Installation review" className="space-y-3 rounded-lg border border-border bg-muted/20 p-4 text-sm">
      <h3 className="font-semibold">Gate Console {review.version}</h3>
      <p>Review URL: {review.temporary_url}</p>
      {review.expires_at && <p>Registration expires {formatDateTime(review.expires_at)}</p>}
      <ul className="list-inside list-disc space-y-1 text-xs">{review.effects.map(effect => <li key={effect}>{effect}</li>)}</ul>
      <p className="text-xs text-muted-foreground">Install Gate and copy your Tally data for review. You’ll approve the final switch after checking Gate.</p>
      <button type="button" disabled={locked || !hostReady} onClick={() => void (status?.status === "failed" ? retry() : prepare())} className={primary}>{status?.status === "failed" ? "Retry upgrade" : "Upgrade to Gate"}</button>
    </section>}
  </form>;

  return <div className="mx-auto max-w-2xl space-y-5">
    <section className="space-y-5 rounded-xl border border-border bg-card p-6">
      <div><h2 className="text-lg font-semibold">Upgrade to Gödel Gate</h2><p className="mt-2 text-sm text-muted-foreground">Enter your installation details to upgrade Tally. Docker and Docker Compose must be running on this host.</p></div>
      {isAdmin === null ? <p role="status" className="text-sm text-muted-foreground">Checking administrator access…</p>
        : !isAdmin ? <p role="status" className="text-sm text-muted-foreground">Sign in as a Tally administrator to upgrade this installation.</p>
        : status?.available === false ? <p role="status" className="text-sm">{status.unavailable_reason}</p>
        : <>
          {!hostReady && <p role="status" className="text-sm text-muted-foreground">The upgrade service is connecting. You can enter your details below.</p>}
          {workingLabel && <p role="status" className="flex items-center gap-2 text-sm"><Loader2 className="size-4 animate-spin" />{workingLabel}</p>}
          {prepareStarted && !started ? <UpgradeProgress status={status} starting /> : started ? <>

        <UpgradeSection>
          <p className="flex items-center gap-2">{running && <Loader2 className="size-4 animate-spin text-primary" />}<strong>{upgradeStageLabels[status!.status] ?? "Checking upgrade status"}</strong>{status!.version ? ` · Gate ${status!.version}` : ""}</p>
          {status!.status !== "cancelled" && <UpgradeProgress status={status!} />}
          {running && <p role="status" className="text-xs text-muted-foreground">Progress updates automatically. You can keep this tab open while the upgrade continues.</p>}
          {status!.progress?.length > 0 && <div className="rounded-lg border border-border bg-background/70 p-3 text-xs"><p className="mb-2 font-semibold">Upgrade activity</p><ol className="space-y-2 border-l border-border pl-3">{status!.progress.map((entry, index) => <li key={`${entry.at}-${index}`} className="relative"><span className="absolute -left-[17px] top-1 size-2 rounded-full bg-primary" /><span className="text-muted-foreground">{formatDateTime(entry.at)}</span><span className="ml-2">{entry.message}</span></li>)}</ol></div>}
          {status!.status === "cutover_failed" && gateFinalChecksPassed && <p>Gate Console: <a className="text-primary underline" href={status!.final_url ?? undefined} target="_blank" rel="noopener noreferrer">{status!.final_url}</a></p>}
          {status!.status === "cutover_failed" && (status!.cutover_retryable || status!.cutover_stage === "activation_failed") && status!.temporary_url && <p>Gate review console: <a className="text-primary underline" href={status!.temporary_url} target="_blank" rel="noopener noreferrer">{status!.temporary_url}</a></p>}
          {status!.expires_at && <p>Registration expires {formatDateTime(status!.expires_at)}</p>}
          {status!.migration_warning && <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm"><p className="font-semibold">Best-effort data transfer</p><p className="mt-1">{status!.migration_warning}</p><p className="mt-2 text-xs text-muted-foreground">Review your transferred data in Gate before approving the switch. Gate must still pass its health and data checks.</p></div>}
          {status!.verification && <div><p className="font-semibold">Copied Tally data verified</p><pre className="mt-2 overflow-auto rounded bg-muted p-3 text-xs">{status!.verification}</pre></div>}
          {status!.status === "failed" && <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><p className="font-semibold text-destructive">Installation stopped before cutover</p><p className="mt-1">{status!.failure_reason || "Installation or data copy failed. Tally writers were resumed when possible."}</p><p className="mt-2 text-xs text-muted-foreground">Tally remains the active installation. The redacted attempt log is shown below.</p>{status!.failure_reason?.includes("cannot decrypt") && <a className="mt-2 inline-block text-xs font-semibold text-primary underline" href="/connectors">Update connector credentials in Tally</a>}<button type="button" disabled={locked} onClick={() => void reset()} className={`${button} mt-3 block bg-background`}>Clear logs and start over</button></div>}
          {status!.status === "cutover_failed" && <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><p className="font-semibold text-destructive">{gateFinalChecksPassed ? "Tally shutdown needs attention" : "The switch to Gate paused"}</p><p className="mt-1">{status!.failure_reason || "The switch needs attention. Review the details below."}</p><p className="mt-2 text-xs text-muted-foreground">Tally and Gate data are retained. The redacted cutover log is shown below.</p></div>}
          {status!.attempt_log && <details className="rounded-lg border border-border bg-background/70 p-3 text-xs">
            <summary className="cursor-pointer font-semibold">{status!.attempt_log.name} · redacted</summary>
            {status!.attempt_log.truncated && <p className="mt-2 text-muted-foreground">Showing the latest 32 KB.</p>}
            <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-muted/50 p-3 font-mono text-[11px] leading-5">{status!.attempt_log.content}</pre>
          </details>}
        </UpgradeSection>
        {status!.status === "ready_for_cutover" && <UpgradeSection>
          <div className="rounded-xl border-2 border-primary/50 bg-primary/10 p-4"><p className="text-base font-semibold">Open the Gate Console here</p><a href={status!.temporary_url ?? undefined} target="_blank" rel="noopener noreferrer" className="break-all text-base font-semibold text-primary underline">{status!.temporary_url}</a><p className="mt-2 text-xs text-muted-foreground">Gate uses a self-signed certificate for this review. Your browser may ask you to inspect and accept it. Sign in with your Tally account and explore the copied data before cutover.</p></div>
          <p>Your Gate installation, transferred data, accounts, and AI Registry decisions have passed the upgrade checks. Tally remains read-only while you review Gate. Confirm or update your final Gate URL below, then enter the host paths for an HTTPS certificate and private key that match that address. Your Tally data and backup will be retained.</p>
          <p className="text-xs text-muted-foreground">Gate’s final HTTPS endpoint is checked before Tally shuts down. If both use the same HTTPS port, Tally’s router pauses briefly during the handoff. Keep your Gate review tab open; this Tally tab will disconnect after Gate is ready.</p>
          <label className="block text-xs font-semibold">Final Gate Console URL<input type="url" value={finalUrl} onChange={event => { setFinalUrl(event.target.value); setError(""); }} disabled={busy || status!.busy} className={field} placeholder="https://console.example.com" /></label>
          <p className="text-xs text-muted-foreground">You can change this address before switching. Point its hostname to this host and choose a certificate that covers it. Your temporary review URL stays the same.</p>
          <label className="flex items-center gap-2 text-xs font-semibold"><input type="checkbox" checked={gateReviewed} onChange={event => setGateReviewed(event.target.checked)} />I signed in and reviewed Gate</label>
          {gateReviewed && <><label className="block text-xs font-semibold">Production TLS full-chain path on this host<input value={tlsCert} onChange={event => setTlsCert(event.target.value)} className={field} placeholder="/path/to/fullchain.pem" /></label>
          <label className="block text-xs font-semibold">Production TLS private-key path on this host<input value={tlsKey} onChange={event => setTlsKey(event.target.value)} className={field} placeholder="/path/to/privkey.pem" /></label></>}
          <div className="flex flex-wrap gap-2"><button type="button" disabled={busy || status!.busy || !gateReviewed || !finalUrl.trim() || !tlsCert.trim() || !tlsKey.trim()} onClick={() => void cutover()} className={primary}>Approve switch to Gate at {finalUrl.trim()}</button><button type="button" disabled={busy || status!.busy} onClick={() => void cancel()} className={button}>Cancel and resume Tally</button></div>
        </UpgradeSection>}
        {status!.status === "cutover_failed" && <UpgradeSection>
          {status!.cutover_retryable ? <>
            <p>The switch paused before Gate activation. Tally remains read-only, and both databases are retained. Review the details above, update the affected settings, then retry when you’re ready.</p>
            <label className="block text-xs font-semibold">Final Gate Console URL<input type="url" value={finalUrl} onChange={event => { setFinalUrl(event.target.value); setError(""); }} disabled={busy || status!.busy} className={field} placeholder="https://console.example.com" /></label>
            <label className="block text-xs font-semibold">Production TLS full-chain path<input value={tlsCert} onChange={event => setTlsCert(event.target.value)} className={field} /></label>
            <label className="block text-xs font-semibold">Production TLS private-key path<input value={tlsKey} onChange={event => setTlsKey(event.target.value)} className={field} /></label>
            <div className="flex flex-wrap gap-2"><button type="button" disabled={busy || status!.busy || !finalUrl.trim() || !tlsCert.trim() || !tlsKey.trim()} onClick={() => void cutover()} className={primary}>Retry switch to Gate at {finalUrl.trim()}</button><button type="button" disabled={busy || status!.busy} onClick={() => void cancel()} className={button}>Cancel and resume Tally</button></div>
          </> : gateFinalChecksPassed ? <p>Gate passed its final HTTPS and service checks. Sign in at the Gate Console link above and review the log to resolve the remaining Tally shutdown issue. Keep Tally writers paused while Gate is active.</p> : <p>This switch needs a recovery review before another attempt. Review the log above to confirm which services are running and whether Gate received new data.</p>}
        </UpgradeSection>}
        {status!.status === "failed" && <UpgradeSection>{detailsForm}</UpgradeSection>}
        {status!.status === "cancelled" && <UpgradeSection><p>Tally has resumed, and your databases and backup are retained. You can start another upgrade when you’re ready. Choose an empty installation folder for the new attempt.</p><button type="button" disabled={busy || status!.busy} onClick={() => void reset()} className={button}>Start a new attempt</button></UpgradeSection>}
        {(status!.status === "cutting_over" || status!.status === "gate_live") && (status!.final_url || status!.requested_final_url) && <UpgradeSection><p>Open <a href={status!.final_url || status!.requested_final_url || undefined} className="text-primary underline">{status!.final_url || status!.requested_final_url}</a>{status!.status === "gate_live" ? " to sign in" : " once Gate is ready"}. Use your Tally email and password. The Tally data remains on this host.</p></UpgradeSection>}

          </> : detailsForm}
        </>}
      {error && <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">{error}</p>}
    </section>
  </div>;
}

function UpgradeSection({ children }: { children: React.ReactNode }) {
  return <section className="space-y-3 text-sm leading-6">{children}</section>;
}
