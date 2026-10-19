"use client";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ConnectorOverview } from "@/components/estate-overview";
import { LoadingState } from "@/components/loading-state";

function Overview() {
  const requested = useSearchParams().get("view");
  const status = requested === "authorization" || requested === "authorization_queue" ? "authorization_queue" : requested === "sanctioned" || requested === "unsanctioned" ? requested : "all";
  return <ConnectorOverview key={status} initialStatus={status}/>;
}
export default function OverviewPage() { return <Suspense fallback={<LoadingState/>}><Overview/></Suspense>; }
