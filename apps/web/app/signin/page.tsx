"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Brand } from "@/components/brand";

type Status = { first_user_registration_open: boolean; email_configured: boolean };
type SignedIn = { email: string; display_name: string };

export default function SignInPage() {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  // An existing session is shown, never silently kept behind a failed sign-in.
  const [signedIn, setSignedIn] = useState<SignedIn | null>(null);
  const [invite, setInvite] = useState("");
  const [register, setRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    const timer = window.setTimeout(() => {
      const token = new URLSearchParams(window.location.hash.slice(1)).get("invite");
      if (token && /^[a-f0-9]{64}$/.test(token)) { setInvite(token); setRegister(true); history.replaceState(null, "", "/signin"); }
    }, 0);
    void fetch("/api/v1/auth/me", { cache: "no-store" })
      .then(response => response.ok ? response.json() as Promise<{ user: SignedIn }> : null)
      .then(body => { if (active && body) setSignedIn(body.user); })
      .catch(() => {});
    const loadStatus = () => {
      void fetch("/api/v1/auth/status", { cache: "no-store", signal: AbortSignal.timeout(4000) })
        .then(response => { if (!response.ok) throw new Error("Authentication unavailable"); return response.json(); })
        .then((value: Status) => {
          if (!active) return;
          setStatus(value); setError(current => current === "Tally authentication is unavailable. Retrying…" ? "" : current);
          if (value.first_user_registration_open) setRegister(true);
        })
        .catch(() => { if (active) setError("Tally authentication is unavailable. Retrying…"); });
    };
    loadStatus();
    const retry = window.setInterval(() => { if (active) loadStatus(); }, 6000);
    return () => { active = false; window.clearTimeout(timer); window.clearInterval(retry); };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const response = await fetch(`/api/v1/auth/${register ? "register" : "login"}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify(register ? { email, first_name: firstName.trim(), last_name: lastName.trim(), password, invitation_token: invite || undefined } : { email, password }),
        signal: AbortSignal.timeout(10000),
      });
      // Any earlier session ended with this attempt, whether or not it succeeded.
      setSignedIn(null);
      if (!response.ok) throw new Error((await response.json()).error || "Sign in failed");
      if (register) {
        setRegister(false);
        setStatus(current => current ? { ...current, first_user_registration_open: false } : current);
      }
      const session = await fetch("/api/v1/auth/me", { cache: "no-store" });
      if (!session.ok) throw new Error(register
        ? "Your account was created, but Tally could not confirm your session. Try signing in."
        : "Tally could not confirm your session. Please try signing in again.");
      router.replace("/"); router.refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Sign in failed"); }
    finally { setBusy(false); }
  }

  async function signOut() {
    setBusy(true);
    try {
      const response = await fetch("/api/v1/auth/logout", { method: "POST" });
      if (!response.ok) throw new Error("Could not sign out. Please try again.");
      setSignedIn(null); router.refresh();
    } catch { setError("Could not sign out. Please try again."); }
    finally { setBusy(false); }
  }

  const first = status?.first_user_registration_open;
  const button = "w-full rounded-md px-4 py-2 font-semibold disabled:opacity-50";
  return <div className="fixed inset-0 z-50 grid place-items-center overflow-y-auto bg-background px-4 py-10">
    <div className="w-full max-w-md rounded-2xl border border-border bg-card p-8 shadow-xl">
      <Brand />
      {signedIn ? <>
        <h1 className="mt-8 text-2xl font-bold">You’re signed in</h1>
        <p className="mt-2 text-sm text-muted-foreground">Signed in as {signedIn.display_name} ({signedIn.email}).{invite ? " Sign out to accept this invitation with another account." : ""}</p>
        {error && <p role="alert" className="mt-4 text-sm text-destructive">{error}</p>}
        <div className="mt-6 space-y-3">
          {!invite && <button type="button" onClick={() => { router.replace("/"); router.refresh(); }} className={`${button} bg-primary text-primary-foreground`}>Continue to Tally</button>}
          <button type="button" onClick={() => void signOut()} disabled={busy} className={`${button} border border-border`}>Sign out</button>
        </div>
      </> : <>
        <h1 className="mt-8 text-2xl font-bold">{first ? "Create the first Tally administrator" : register ? "Accept your Tally invitation" : "Sign in to Tally"}</h1>
        <p className="mt-2 text-sm text-muted-foreground">{first ? "The first account is the Tally administrator and invites everyone else." : register ? "Use the email address on your invitation." : "Enter your email and password."}</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          {register && <div className="grid gap-4 sm:grid-cols-2">
            <label className="block text-sm font-medium">First name<input required maxLength={100} value={firstName} onChange={e => setFirstName(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background p-2" autoComplete="given-name" /></label>
            <label className="block text-sm font-medium">Last name<input required maxLength={100} value={lastName} onChange={e => setLastName(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background p-2" autoComplete="family-name" /></label>
          </div>}
          {register && !first && <label className="block text-sm font-medium">Invitation token<input required value={invite} onChange={e => setInvite(e.target.value.trim())} className="mt-1 w-full rounded-md border border-border bg-background p-2" autoComplete="off" placeholder="Paste the token from your invitation link" /></label>}
          <label className="block text-sm font-medium">Email<input required type="email" value={email} onChange={e => setEmail(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background p-2" autoComplete="email" /></label>
          <label className="block text-sm font-medium">Password<input required type="password" minLength={register ? 12 : undefined} value={password} onChange={e => setPassword(e.target.value)} className="mt-1 w-full rounded-md border border-border bg-background p-2" autoComplete={register ? "new-password" : "current-password"} /></label>
          {!register && <p className="-mt-1 text-right text-sm"><Link href="/forgot-password" className="text-primary">Forgot password?</Link></p>}
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <button disabled={busy || !status} className={`${button} bg-primary text-primary-foreground`}>{busy ? "Please wait…" : register ? "Create account" : "Sign in"}</button>
        </form>
        {!first && !invite && <button type="button" onClick={() => setRegister(!register)} className="mt-4 text-sm text-primary">{register ? "Return to sign in" : "Have an invitation?"}</button>}
      </>}
    </div>
  </div>;
}
