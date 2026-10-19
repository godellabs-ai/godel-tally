"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

export type CurrentUser = { id: string; email: string; display_name: string; role: "admin" | "member" };

const authPages = new Set(["/signin", "/forgot-password", "/reset-password"]);
export const isAuthPage = (pathname: string) => authPages.has(pathname);

// The shell stays mounted across sign-in, so one lookup is shared and refreshed after it.
let lookup: Promise<CurrentUser | null> | null = null;

function load(): Promise<CurrentUser | null> {
  lookup ??= fetch("/api/v1/auth/me", { cache: "no-store" })
    .then(response => response.ok ? response.json() as Promise<{ user: CurrentUser }> : null)
    .then(body => body?.user ?? null, () => null);
  return lookup;
}

/** The signed-in Tally user; `undefined` while loading and `null` when signed out. */
export function useCurrentUser(): CurrentUser | null | undefined {
  const pathname = usePathname();
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined);
  useEffect(() => {
    if (authPages.has(pathname)) { lookup = null; return; }
    let active = true;
    void load().then(next => { if (active) setUser(next); });
    return () => { active = false; };
  }, [pathname]);
  return isAuthPage(pathname) ? null : user;
}
