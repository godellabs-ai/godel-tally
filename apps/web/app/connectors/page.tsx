"use client";
import { ConnectorsHub } from "@/components/connectors-hub";
import { PageData } from "@/components/page-data";
import { getTallyConnectors, getTallyScans } from "@/lib/tally";
async function load() {
  const [connectors, scans] = await Promise.all([getTallyConnectors(), getTallyScans()]);
  return connectors && scans ? { connectors, scans } : null;
}
export default function ConnectorsPage() {
  return <PageData load={load}>{data => <ConnectorsHub initialData={data.connectors} initialScans={data.scans.items} />}</PageData>;
}
