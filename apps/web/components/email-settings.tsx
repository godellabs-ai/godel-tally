"use client";

import { LoaderCircle, Mail, Send } from "lucide-react";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { authFetch } from "../lib/session";

type Provider = "smtp" | "ses" | "sendgrid" | "mailgun" | "postmark" | "resend";
type EmailView = {
  configured: boolean; source: "database" | "environment" | null; enabled: boolean; provider: Provider;
  from_email: string; from_name: string | null; settings: Record<string, string>; secrets_set: string[];
  public_url_configured: boolean;
};
type Field = { key: string; label: string; secret?: boolean; placeholder?: string; options?: [string, string][]; hint?: string };

const providers: [Provider, string][] = [["smtp", "SMTP"], ["ses", "AWS SES"], ["sendgrid", "SendGrid"], ["mailgun", "Mailgun"], ["postmark", "Postmark"], ["resend", "Resend"]];
const fields: Record<Provider, Field[]> = {
  smtp: [
    { key: "host", label: "SMTP host", placeholder: "smtp.example.com" },
    { key: "port", label: "Port", placeholder: "587" },
    { key: "security", label: "Security", options: [["starttls", "STARTTLS (recommended)"], ["tls", "TLS"], ["none", "None"]] },
    { key: "username", label: "Username", placeholder: "Leave empty for no authentication" },
    { key: "password", label: "Password", secret: true },
  ],
  ses: [
    { key: "region", label: "AWS region", placeholder: "us-east-1" },
    { key: "access_key_id", label: "Access key ID", secret: true, hint: "Optional. Leave both keys empty to use this host’s AWS credentials." },
    { key: "secret_access_key", label: "Secret access key", secret: true },
  ],
  sendgrid: [{ key: "api_key", label: "API key", secret: true, placeholder: "SG.…" }],
  mailgun: [
    { key: "domain", label: "Sending domain", placeholder: "mg.example.com" },
    { key: "region", label: "Region", options: [["us", "US"], ["eu", "EU"]] },
    { key: "api_key", label: "API key", secret: true },
  ],
  postmark: [{ key: "server_token", label: "Server token", secret: true }],
  resend: [{ key: "api_key", label: "API key", secret: true, placeholder: "re_…" }],
};
const select = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm";

async function call<T>(path: string, body?: unknown): Promise<T> {
  const response = await authFetch(path, body === undefined ? { cache: "no-store" }
    : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.error ?? "Email settings are unavailable.");
  return data as T;
}

/** Outbound email for password reset links. */
export function EmailSettings() {
  const [view, setView] = useState<EmailView | null>(null);
  const [enabled, setEnabled] = useState(true);
  const [provider, setProvider] = useState<Provider>("smtp");
  const [fromEmail, setFromEmail] = useState("");
  const [fromName, setFromName] = useState("");
  const [settings, setSettings] = useState<Record<string, string>>({});
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [testTo, setTestTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  function apply(next: EmailView) {
    setView(next); setEnabled(next.source === null || next.enabled); setProvider(next.provider);
    setFromEmail(next.from_email); setFromName(next.from_name ?? ""); setSettings(next.settings); setSecrets({});
  }
  useEffect(() => { void call<EmailView>("email").then(apply, (e: Error) => setMessage({ ok: false, text: e.message })); }, []);

  async function save(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setMessage(null);
    try {
      const keys = new Set(fields[provider].map(f => f.key));
      apply(await call<EmailView>("email", {
        provider, enabled, from_email: fromEmail.trim(), from_name: fromName.trim() || null,
        settings: Object.fromEntries(Object.entries(settings).filter(([k]) => keys.has(k) && !fields[provider].find(f => f.key === k)?.secret)),
        secrets: Object.fromEntries(Object.entries(secrets).filter(([k, v]) => keys.has(k) && v.trim())),
      }));
      setMessage({ ok: true, text: enabled ? "Email settings saved." : "Email settings saved. Email is turned off." });
    } catch (e) { setMessage({ ok: false, text: e instanceof Error ? e.message : "Email settings could not be saved." }); }
    finally { setBusy(false); }
  }
  async function test() {
    setBusy(true); setMessage(null);
    try {
      const result = await call<{ sent: boolean; message: string }>("email/test", { to: testTo.trim() });
      setMessage({ ok: result.sent, text: result.message });
    } catch (e) { setMessage({ ok: false, text: e instanceof Error ? e.message : "The test email could not be sent." }); }
    finally { setBusy(false); }
  }

  const saved = (key: string) => view?.provider === provider && view.secrets_set.includes(key);
  return <Card className="gap-0 overflow-hidden py-0">
    <div className="border-b border-border bg-muted/25 px-5 py-4"><h2 className="flex items-center gap-2 text-sm font-bold"><Mail className="size-4 text-primary" />Email delivery</h2><p className="mt-0.5 text-xs text-muted-foreground">Tally emails password reset links. Without email, only an administrator can issue reset links from Users.</p></div>
    {!view ? <p className="flex items-center gap-2 p-5 text-xs text-muted-foreground">{message ? message.text : <><LoaderCircle className="size-3.5 animate-spin" />Loading email settings…</>}</p> : <form onSubmit={save} className="space-y-4 p-5">
      {view.source === "environment" && <p className="rounded-md bg-muted/50 p-3 text-xs">Email is configured with environment variables. Saved settings override them, including turning email off.</p>}
      {!view.public_url_configured && <p className="rounded-md border border-amber-400/50 bg-amber-50 p-3 text-xs text-amber-900 dark:bg-amber-950/30 dark:text-amber-200">Tally doesn’t know its public URL (TALLY_URL), so it won’t email reset links yet. Restart Tally with TALLY_URL set to this console’s address.</p>}
      <label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={enabled} onChange={e => setEnabled(e.target.checked)} className="size-4 accent-primary" />Send email from Tally</label>
      <div className="grid gap-4 sm:grid-cols-2">
        <label className="text-xs font-semibold">Provider<select aria-label="Email provider" value={provider} onChange={e => { setProvider(e.target.value as Provider); setSecrets({}); }} className={`${select} mt-1`}>{providers.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label>
        <label className="text-xs font-semibold">From email<Input required type="email" value={fromEmail} onChange={e => setFromEmail(e.target.value)} placeholder="tally@example.com" className="mt-1" /></label>
        <label className="text-xs font-semibold">From name<Input value={fromName} onChange={e => setFromName(e.target.value)} placeholder="Gödel Tally" className="mt-1" /></label>
        {fields[provider].map(field => <label key={field.key} className="text-xs font-semibold">{field.label}
          {field.options ? <select aria-label={field.label} value={settings[field.key] ?? field.options[0][0]} onChange={e => setSettings(s => ({ ...s, [field.key]: e.target.value }))} className={`${select} mt-1`}>{field.options.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
            : field.secret ? <Input type="password" autoComplete="new-password" value={secrets[field.key] ?? ""} onChange={e => setSecrets(s => ({ ...s, [field.key]: e.target.value }))} placeholder={saved(field.key) ? "Saved · leave blank to keep" : field.placeholder ?? ""} className="mt-1" />
            : <Input value={settings[field.key] ?? ""} onChange={e => setSettings(s => ({ ...s, [field.key]: e.target.value }))} placeholder={field.placeholder} className="mt-1" />}
          {field.hint && <span className="mt-1 block font-normal text-muted-foreground">{field.hint}</span>}
        </label>)}
      </div>
      <div className="flex flex-wrap items-center gap-2"><Button type="submit" disabled={busy}>{busy && <LoaderCircle className="size-3.5 animate-spin" />}Save email settings</Button></div>
      <div className="flex flex-wrap items-end gap-2 border-t border-border pt-4"><label className="min-w-56 flex-1 text-xs font-semibold">Send a test email to<Input type="email" value={testTo} onChange={e => setTestTo(e.target.value)} placeholder="you@example.com" className="mt-1" /></label><Button type="button" variant="outline" disabled={busy || !testTo.trim() || !view.configured} onClick={() => void test()}><Send className="size-3.5" />Send test</Button></div>
      {message && <p role={message.ok ? "status" : "alert"} className={`break-words text-xs ${message.ok ? "text-muted-foreground" : "text-destructive"}`}>{message.text}</p>}
    </form>}
  </Card>;
}
