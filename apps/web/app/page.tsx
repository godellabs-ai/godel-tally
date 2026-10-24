"use client";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ConnectorOverview } from "@/components/estate-overview";
import { LoadingState } from "@/components/loading-state";

function Overview() {
  const params = useSearchParams();
  const requested = params.get("view");
  const query = (params.get("q") ?? "").slice(0,256);
  const status = requested === "authorization" || requested === "authorization_queue" ? "authorization_queue" : requested === "sanctioned" || requested === "unsanctioned" ? requested : "all";
  return <ConnectorOverview key={`${status}:${query}`} initialStatus={status} initialQuery={query}/>;
}
export default function OverviewPage() { return <Suspense fallback={<LoadingState/>}><Overview/></Suspense>; }
