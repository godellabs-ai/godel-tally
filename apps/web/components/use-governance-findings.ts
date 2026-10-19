"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { tallyFetch, type GovernanceFindingsResponse } from "../lib/tally";

export function useGovernanceFindings() {
  const [data, setData] = useState<GovernanceFindingsResponse | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const pending = useRef<AbortController | null>(null);
  const refresh = useCallback(async () => {
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setLoading(true);
    setError("");
    try {
      const response = await tallyFetch("/findings", { cache: "no-store", signal: controller.signal });
      if (!response.ok) throw new Error("Findings are unavailable. Refresh to try again.");
      const next: GovernanceFindingsResponse = await response.json();
      if (!controller.signal.aborted) setData(next);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Findings are unavailable.");
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }, []);
  useEffect(() => {
    const timer = window.setTimeout(() => void refresh(), 0);
    return () => { window.clearTimeout(timer); pending.current?.abort(); };
  }, [refresh]);
  function changed(next?: GovernanceFindingsResponse) {
    // A saved decision must win over any older refresh still in flight.
    pending.current?.abort();
    if (next) { setData(next); setError(""); setLoading(false); }
    else void refresh();
  }
  return { data, error, loading, refresh, changed };
}
