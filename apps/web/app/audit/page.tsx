"use client";
import { AuditWorkspace } from "@/components/audit-workspace";
import { PageData } from "@/components/page-data";
import { getTallyAudit } from "@/lib/tally";
export default function AuditPage() {
  return <PageData load={getTallyAudit}>{data => <AuditWorkspace events={data.items} />}</PageData>;
}
