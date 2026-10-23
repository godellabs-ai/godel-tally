"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { authFetch } from "./session";

export type CurrentUser = { id: string; email: string; display_name: string; role: "admin" | "member" };

const authPages = new Set(["/signin", "/forgot-password", "/reset-password"]);
export const isAuthPage = (pathname: string) => authPages.has(pathname);

// The shell stays mounted across sign-in, so one lookup is shared and refreshed after it.
let lookup: Promise<CurrentUser | null> | null = null;

function load(): Promise<CurrentUser | null> {
  if (!lookup) {
    const pending = authFetch("me", { cache: "no-store", signal: AbortSignal.timeout(5000) })
      .then(response => {
        if (response.status === 401) return null;
        if (!response.ok) throw new Error("Account lookup unavailable");
        return response.json() as Promise<{ user: CurrentUser }>;
      })
      .then(body => body?.user ?? null);
    lookup = pending;
    // Do not cache an outage as a signed-out user, or clear a newer session's lookup.
    void pending.catch(() => { if (lookup === pending) lookup = null; });
  }
  return lookup;
}

/** The signed-in Tally user; `undefined` while loading and `null` when signed out. */
export function useCurrentUser(): CurrentUser | null | undefined {
  const pathname = usePathname();
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined);
  useEffect(() => {
    if (authPages.has(pathname)) { lookup = null; return; }
    let active = true, pending = false;
    let retry: ReturnType<typeof setTimeout>;
    const refresh = () => {
      if (!active || pending) return;
      clearTimeout(retry); pending = true;
      void load().then(next => { if (active) setUser(next); }, () => {
        if (active) retry = setTimeout(refresh, 5000);
      }).finally(() => { pending = false; });
    };
    refresh();
    window.addEventListener("online", refresh); window.addEventListener("focus", refresh);
    return () => {
      active = false; clearTimeout(retry);
      window.removeEventListener("online", refresh); window.removeEventListener("focus", refresh);
    };
  }, [pathname]);
  return isAuthPage(pathname) ? null : user;
}
