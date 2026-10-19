"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Brand } from "@/components/brand";

export default function ResetPasswordPage() {
  const [token, setToken] = useState("");
  const [loaded, setLoaded] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const value = new URLSearchParams(window.location.hash.slice(1)).get("token") ?? "";
      setToken(/^[a-f0-9]{64}$/.test(value) ? value : "");
      setLoaded(true);
      window.history.replaceState(window.history.state, "", "/reset-password");
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (password !== confirmPassword) { setError("New passwords do not match."); return; }
    setBusy(true); setError("");
    try {
      const response = await fetch("/api/v1/auth/password-reset/confirm", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ token, new_password: password }),
      });
      if (!response.ok) throw new Error((await response.json()).error || "Could not reset password.");
      setToken(""); setPassword(""); setConfirmPassword(""); setDone(true);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not reset password."); }
    finally { setBusy(false); }
  }

  const field = "mt-1 w-full rounded-md border border-border bg-background p-2";
  return <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-background px-4 py-10">
    <div className="w-full max-w-md rounded-2xl border border-border bg-card p-8 shadow-xl">
      <Brand /><h1 className="mt-8 text-2xl font-bold">Reset your Tally password</h1>
      {!loaded ? <p role="status" className="mt-5 text-sm text-muted-foreground">Opening reset link…</p>
        : done ? <div className="mt-5 space-y-4"><p role="status" className="text-sm">Your password was changed. Sign in with the new password.</p><Link href="/signin" className="inline-block rounded-md bg-primary px-4 py-2 font-semibold text-primary-foreground">Sign in</Link></div>
        : token ? <form onSubmit={submit} className="mt-6 space-y-4">
          <label className="block text-sm font-medium">New password<input required type="password" minLength={12} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} className={field} /></label>
          <label className="block text-sm font-medium">Confirm new password<input required type="password" minLength={12} autoComplete="new-password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} className={field} /></label>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <button disabled={busy} className="w-full rounded-md bg-primary px-4 py-2 font-semibold text-primary-foreground disabled:opacity-50">{busy ? "Saving…" : "Set new password"}</button>
        </form> : <p role="alert" className="mt-5 text-sm text-destructive">This reset link is missing or invalid. <Link href="/forgot-password" className="underline">Request a new link</Link>, or ask your Tally administrator.</p>}
    </div>
  </div>;
}
