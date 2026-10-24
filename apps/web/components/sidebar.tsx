"use client";

import {
  Bot,
  Cable,
  ClipboardClock,
  LayoutDashboard,
  PanelLeft,
  Settings,
  ArrowUpCircle,
  Users,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { Brand } from "@/components/brand";
import { isAuthPage, useCurrentUser } from "@/lib/current-user";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

const primaryItems = [
  ["Overview", "/", LayoutDashboard],
  ["Connectors", "/connectors", Cable],
  ["People & devices", "/inventory", Users],
  ["AI Registry", "/registry", Bot],
  ["Upgrade", "/upgrade", ArrowUpCircle],
] as const;

const adminItems = [
  ["Users", "/users", Users],
  ["Audit logs", "/audit", ClipboardClock],
  ["Settings", "/settings", Settings],
] as const;

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  // Administration is hidden from members; Tally also refuses these APIs for them.
  const admin = useCurrentUser()?.role === "admin";

  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      setCollapsed(localStorage.getItem("godel_tally_sidebar_collapsed") === "true");
    });
    return () => window.cancelAnimationFrame(frame);
  }, []);

  function toggleCollapsed() {
    setCollapsed((current) => {
      const next = !current;
      localStorage.setItem("godel_tally_sidebar_collapsed", String(next));
      return next;
    });
  }

  if (isAuthPage(pathname)) return null;

  return (
    <TooltipProvider delayDuration={0}>
      <aside
        className={cn(
          "group hidden h-dvh shrink-0 flex-col border-r border-border/10 bg-card transition-all duration-300 relative md:flex",
          collapsed ? "w-16" : "w-52"
        )}
      >
      {/* Sidebar Header with Brand & Primary Collapse Button */}
      <div
        className={cn(
          "flex h-16 shrink-0 items-center",
          collapsed ? "justify-center px-0" : "justify-between gap-2 px-4"
        )}
      >
        {collapsed ? (
          <div className="relative flex size-8 items-center justify-center">
            <Link
              href="/"
              className="flex size-8 items-center justify-center transition-opacity hover:opacity-80 group-hover:hidden"
            >
              <Brand collapsed={true} />
            </Link>

            <button
              type="button"
              onClick={toggleCollapsed}
              aria-label="Expand sidebar"
              className="hidden size-8 items-center justify-center rounded-md bg-primary text-primary-foreground shadow-xs transition-colors hover:bg-primary/90 cursor-pointer group-hover:flex"
            >
              <PanelLeft className="size-4" />
            </button>
          </div>
        ) : (
          <>
            <Link
              href="/"
              className="inline-flex items-center transition-opacity hover:opacity-80"
            >
              <Brand collapsed={false} className="[&_img]:h-7" />
            </Link>

            <button
              type="button"
              onClick={toggleCollapsed}
              aria-label="Collapse sidebar"
              className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground shadow-xs transition-colors hover:bg-primary/90 cursor-pointer"
            >
              <PanelLeft className="size-4" />
            </button>
          </>
        )}
      </div>

      <nav className="flex flex-1 flex-col gap-1.5 overflow-y-auto px-3 py-1" aria-label="Primary navigation">
        {primaryItems.map(([label, href, Icon]) => (
          <NavItem
            key={href}
            label={label}
            href={href}
            icon={Icon}
            active={isActive(pathname, href)}
            collapsed={collapsed}
          />
        ))}

        {admin && (!collapsed ? (
          <div className="mt-4 px-3 pb-1 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            Admin
          </div>
        ) : (
          <div className="mx-auto my-2 h-px w-8 bg-border" />
        ))}

        {admin && adminItems.map(([label, href, Icon]) => (
          <NavItem
            key={href}
            label={label}
            href={href}
            icon={Icon}
            active={isActive(pathname, href)}
            collapsed={collapsed}
          />
        ))}
      </nav>

    </aside>
  </TooltipProvider>
  );
}

function NavItem({
  label,
  href,
  icon: Icon,
  active,
  collapsed,
}: {
  label: string;
  href: string;
  icon: typeof LayoutDashboard;
  active: boolean;
  collapsed: boolean;
}) {
  const link = (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "group flex items-center rounded-lg text-sm font-medium transition-all w-full",
        collapsed ? "justify-center py-2 px-0" : "gap-2.5 px-3 py-2",
        active
          ? "bg-primary/10 text-foreground font-semibold"
          : "text-muted-foreground hover:bg-accent hover:text-foreground"
      )}
    >
      <Icon
        className={cn(
          "size-4 shrink-0",
          active ? "text-primary" : "text-muted-foreground"
        )}
        strokeWidth={2.1}
      />
      {!collapsed && <span>{label}</span>}
    </Link>
  );

  if (collapsed) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>{link}</TooltipTrigger>
        <TooltipContent side="right" className="font-medium">
          {label}
        </TooltipContent>
      </Tooltip>
    );
  }

  return link;
}

function isActive(pathname: string, href: string) {
  return href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);
}
