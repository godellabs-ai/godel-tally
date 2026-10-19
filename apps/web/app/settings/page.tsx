"use client";
import { DataRemoval } from "@/components/data-removal";
import { EmailSettings } from "@/components/email-settings";
import { PageData } from "@/components/page-data";
import { getDataInventory } from "@/lib/tally";
async function load() {
  const response = await fetch("/api/v1/auth/me", { cache: "no-store", signal: AbortSignal.timeout(5000) });
  if (!response.ok) return null;
  const body = await response.json() as { user?: { role?: string } };
  if (body.user?.role !== "admin") return { admin: false, inventory: null };
  const inventory = await getDataInventory();
  return inventory ? { admin: true, inventory } : null;
}
export default function SettingsPage() {
  return <PageData load={load}>{data => data.admin ? <div className="space-y-6"><EmailSettings /><DataRemoval initialInventory={data.inventory} /></div>
    : <p role="alert" className="rounded-xl border border-border bg-card p-5 text-sm text-muted-foreground">Administrator access is required to view Tally settings.</p>}</PageData>;
}
