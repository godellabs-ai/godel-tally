"use client";

import { useEffect, useState, type ReactNode } from "react";
import Link from "next/link";
import { LoadingState } from "@/components/loading-state";
import { accessDeniedSince } from "@/lib/tally";

/** Standalone pages fetch after authentication; exported HTML never contains customer data. */
export function PageData<T>({ load, children }: { load: () => Promise<T | null>; children: (data: T) => ReactNode }) {
  const [result, setResult] = useState<{ data: T | null; failed: boolean; denied: boolean } | null>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    const started = Date.now();
    void load().then(data => { if (active) setResult({ data, failed: data === null, denied: data === null && accessDeniedSince(started) }); })
      .catch(() => { if (active) setResult({ data: null, failed: true, denied: accessDeniedSince(started) }); });
    return () => { active = false; };
  }, [load, attempt]);
  if (!result) return <LoadingState />;
  if (result.denied) return <div role="alert" className="rounded-xl border border-border bg-card p-5 text-sm">
    This page is available to Tally administrators. Ask an administrator if you need access.
    <Link href="/" className="ml-3 underline">Go to Overview</Link>
  </div>;
  if (result.failed || result.data === null) return <div role="alert" className="rounded-xl border border-border bg-card p-5 text-sm">
    Could not load this page. Check your connection and access permissions.
    <button className="ml-3 underline" onClick={() => { setResult(null); setAttempt(value => value + 1); }}>Retry</button>
  </div>;
  return children(result.data);
}
