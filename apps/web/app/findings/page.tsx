"use client";
import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { LoadingState } from "@/components/loading-state";
function Findings() {
  const router = useRouter();
  const requested = useSearchParams().get("view");
  const view = requested === "authorization" || requested === "authorization_queue" || requested === "sanctioned" || requested === "unsanctioned" ? requested : "all";
  useEffect(() => { router.replace(`/?view=${view}#findings`); }, [router, view]);
  return <LoadingState/>;
}
export default function FindingsPage() { return <Suspense fallback={<LoadingState />}><Findings /></Suspense>; }
