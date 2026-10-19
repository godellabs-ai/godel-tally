"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import { tallyFetch, setRegistrySanction } from "../lib/tally";
import { estateRecordIds, type EstateRecord, type EstateResponse, type EstateReviewAction } from "../lib/estate";

export function useEstateInventory(path = "/estate") {
  const [data, setData] = useState<EstateResponse | null>(null), [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const pending = useRef<AbortController | null>(null);
  const loadedCount = useRef(0);
  const load = useCallback(async (after?: string) => {
    pending.current?.abort();
    const controller = new AbortController(); pending.current = controller;
    setLoading(true); setError("");
    try {
      async function page(cursor?: string) {
        const response = await tallyFetch(`${path}?limit=2000${cursor ? `&after=${encodeURIComponent(cursor)}` : ""}`, { cache: "no-store", signal: controller.signal });
        if (!response.ok) throw new Error("Connector inventory is unavailable.");
        return await response.json() as EstateResponse;
      }
      const next = await page(after);
      const visited = new Set<string>();
      // Refresh the loaded extent, so a review or refresh does not drop later pages.
      while (!after && next.next_cursor && next.records.length < loadedCount.current) {
        if (visited.has(next.next_cursor)) throw new Error("Inventory returned a repeated page cursor.");
        visited.add(next.next_cursor);
        const more = await page(next.next_cursor);
        next.records = [...new Map([...next.records, ...more.records].map(record => [record.id, record])).values()];
        next.next_cursor = more.next_cursor;
      }
      if (controller.signal.aborted) return;
      setData(previous => {
        const records = [...new Map([...(after ? previous?.records ?? [] : []), ...next.records].map(record => [record.id, record])).values()];
        loadedCount.current = records.length;
        return { ...next, records };
      });
    } catch (cause) { if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Connector inventory is unavailable."); }
    finally { if (!controller.signal.aborted) setLoading(false); }
  }, [path]);
  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => { window.clearTimeout(timer); pending.current?.abort(); };
  }, [load]);
  const review = async (record: EstateRecord, action: EstateReviewAction) => {
    if (record.registry_id && (action === "sanction" || action === "unsanction")) {
      const result = await setRegistrySanction(record.detail.kind === "model" ? "model" : "provider", [record.registry_id], action === "sanction");
      if (!result.ok) throw new Error(result.error);
    } else {
      const ids = action === "flag" || action === "clear_flag" ? estateRecordIds(record) : [record.id];
      for (const id of ids) {
        const result = await tallyFetch("/registry/estate-reviews", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ entity_id: id, action }) });
        if (!result.ok) throw new Error(result.status === 403 ? "Your role cannot update AI review decisions." : "Could not save the review decision.");
      }
    }
    await load();
  };
  return { data, error, loading, review, refresh: () => void load(), loadMore: data?.next_cursor ? () => void load(data.next_cursor!) : undefined };
}
