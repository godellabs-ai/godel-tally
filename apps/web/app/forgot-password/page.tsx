"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Brand } from "@/components/brand";

export default function ForgotPasswordPage() {
  const [emailConfigured, setEmailConfigured] = useState<boolean | null>(null);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    void fetch("/api/v1/auth/status", { cache: "no-store", signal: AbortSignal.timeout(5000) })
      .then(response => response.ok ? response.json() as Promise<{ email_configured: boolean }> : Promise.reject())
      .then(status => { if (active) setEmailConfigured(status.email_configured); })
      .catch(() => { if (active) setError("Tally authentication is unavailable. Reload this page to try again."); });
    return () => { active = false; };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const response = await fetch("/api/v1/auth/password-reset/request", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email }),
        signal: AbortSignal.timeout(10000),
      });
      if (response.status === 503) { setEmailConfigured(false); return; }
      if (!response.ok) throw new Error((await response.json()).error || "Could not request a reset link.");
      setSent(true);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not request a reset link."); }
    finally { setBusy(false); }
  }

  return <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-background px-4 py-10">
    <div className="w-full max-w-md rounded-2xl border border-border bg-card p-8 shadow-xl">
      <Brand /><h1 className="mt-8 text-2xl font-bold">Reset your password</h1>
      {emailConfigured === null && !error ? <p role="status" className="mt-5 text-sm text-muted-foreground">Checking password reset options…</p>
        : emailConfigured === false ? <div role="status" className="mt-5 space-y-3 text-sm leading-6">
          <p>Email isn’t set up for this Tally installation, so Tally can’t send you a reset link.</p>
          <p className="text-muted-foreground">Ask a Tally administrator to send you a reset link from <strong>Users</strong>.</p>
          <p className="text-muted-foreground">If no administrator can sign in, ask whoever runs Tally to configure email delivery on the server. Resetting the database is a last resort: it deletes all Tally data and accounts. The first account registered afterwards becomes the administrator.</p>
        </div>
        : sent ? <p role="status" className="mt-5 text-sm leading-6">If a Tally account uses <strong>{email}</strong>, a reset link is on its way. It works once and expires in one hour.</p>
        : <form onSubmit={submit} className="mt-6 space-y-4">
          <p className="text-sm text-muted-foreground">Enter your account’s email address and Tally will email you a link to set a new password.</p>
          <label className="block text-sm font-medium">Email<input required type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} className="mt-1 w-full rounded-md border border-border bg-background p-2" /></label>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <button disabled={busy} className="w-full rounded-md bg-primary px-4 py-2 font-semibold text-primary-foreground disabled:opacity-50">{busy ? "Sending…" : "Email me a reset link"}</button>
        </form>}
      {error && emailConfigured === null && <p role="alert" className="mt-5 text-sm text-destructive">{error}</p>}
      <Link href="/signin" className="mt-6 inline-block text-sm text-primary">Back to sign in</Link>
    </div>
  </div>;
}
