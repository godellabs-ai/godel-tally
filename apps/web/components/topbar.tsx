"use client";

import { Bot, Cable, ClipboardClock, LayoutDashboard, Menu, Settings, ArrowUpCircle, Users, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { Brand } from "@/components/brand";
import { ThemeToggle } from "@/components/theme-toggle";
import { isAuthPage, useCurrentUser } from "@/lib/current-user";

const routes = [
  ["/", "Overview", "AI findings, authorization decisions and connections across your estate.", LayoutDashboard],
  ["/connectors", "Connectors", "Add and manage discovery sources.", Cable],
  ["/inventory", "People & devices", "Users and devices observed across your discovery sources.", Users],
  ["/registry", "AI Registry", "Manage provider and model sanctions.", Bot],
  ["/upgrade", "Upgrade", "Upgrade this Tally installation to Gödel Gate.", ArrowUpCircle],
  ["/audit", "Audit logs", "Administrative and operational changes.", ClipboardClock],
  ["/settings", "Settings", "Email delivery, stored data and data removal.", Settings],
  ["/users", "Users", "Manage Tally console access.", Users],
] as const;
const adminRoutes = new Set<string>(["/audit", "/settings", "/users"]);

export function Topbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const admin = useCurrentUser()?.role === "admin";
  const menu = routes.filter(([href]) => admin || !adminRoutes.has(href));
  const route = routes.find(([prefix]) => prefix === "/" ? pathname === "/" : pathname.startsWith(prefix)) ?? routes[0];
  const [, title, subtitle, Icon] = route;
  if (isAuthPage(pathname)) return null;

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between gap-4 border-b border-border/10 bg-card/95 px-6 backdrop-blur transition-colors duration-300">
      <div className="flex min-w-0 items-center gap-3.5">
        <button type="button" aria-label={menuOpen ? "Close navigation" : "Open navigation"} onClick={() => setMenuOpen((open) => !open)} className="grid size-9 place-items-center rounded-lg border border-border md:hidden">{menuOpen ? <X className="size-4" /> : <Menu className="size-4" />}</button>
        <div className="md:hidden"><Brand /></div>
        <span className="hidden size-8 shrink-0 place-items-center rounded-md bg-primary/10 text-primary md:grid"><Icon className="size-4" /></span>
        <div className="min-w-0"><h1 className="truncate text-xl font-bold leading-tight tracking-tight md:text-2xl">{title}</h1><p className="mt-0.5 truncate text-[13px] leading-tight text-muted-foreground">{subtitle}</p></div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <ThemeToggle />
        <button type="button" onClick={async () => { await fetch("/api/v1/auth/logout", { method: "POST" }); router.replace("/signin"); router.refresh(); }} className="rounded-md border border-border px-3 py-1.5 text-xs font-semibold">Sign out</button>
      </div>
      {menuOpen ? <nav aria-label="Mobile navigation" className="fixed inset-x-0 top-16 border-b border-border bg-card p-3 shadow-xl md:hidden"><div className="grid gap-1">{menu.map(([href, label, , NavIcon]) => <Link key={href} href={href} onClick={() => setMenuOpen(false)} className={`flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-bold ${isActive(pathname, href) ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:bg-accent"}`}><NavIcon className={`size-4 ${isActive(pathname, href) ? "text-primary" : ""}`} />{label}</Link>)}</div></nav> : null}
    </header>
  );
}
function isActive(pathname: string, href: string) { return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`); }
