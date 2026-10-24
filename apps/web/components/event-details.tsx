"use client";

import { FindingActivity } from "./finding-activity";
import { useState, type ReactNode } from "react";
import { ArrowRight, Bot, Check, ChevronDown, Copy, Globe, Laptop, Plug, ShieldCheck, ShieldQuestion, ShieldX, UserRound } from "lucide-react";
import { Drawer, DrawerContent, DrawerDescription, DrawerTitle } from "@/components/ui/drawer";
import { Button } from "@/components/ui/button";
import { authorizationReason, eventActivity, eventDestination, eventHandoff, eventLabel, eventModels, eventPerson, eventProviders, eventStatus, sourceAddresses, type EventRow, type EventStatus } from "../lib/event-stream";
import { formatDateTime } from "../lib/datetime";
import { connectorTypeLabel } from "../lib/connector-catalog";

const statusStyle = {
  unsanctioned: { label: "Unsanctioned", icon: ShieldX, className: "border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-400" },
  authorization_queue: { label: "Authorization Queue", icon: ShieldQuestion, className: "border-amber-500/25 bg-amber-500/10 text-amber-800 dark:text-amber-400" },
  sanctioned: { label: "Sanctioned", icon: ShieldCheck, className: "border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" },
};
export function EventStatusBadge({ status }: { status: EventStatus }) {
  const style = statusStyle[status], Icon = style.icon;
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-1 text-[10px] font-bold ${style.className}`}><Icon className="size-3.5 shrink-0"/>{style.label}</span>;
}

export function EventDetails({ row, onClose, onInvestigate }: { row: EventRow | null; onClose: () => void; onInvestigate: (query: string) => void }) {
  const [current, setCurrent] = useState(row);
  if (row && row !== current) setCurrent(row);
  return <Drawer open={Boolean(row)} onOpenChange={open => { if (!open) onClose(); }}>
    <DrawerContent showTOC>{current ? <EventDetailsBody key={current.event.observation_id} row={current} onInvestigate={onInvestigate}/> : null}</DrawerContent>
  </Drawer>;
}
function EventDetailsBody({ row, onInvestigate }: { row: EventRow; onInvestigate: (query: string) => void }) {
  const e = row.event, person = eventPerson(e), ips = sourceAddresses(e), destination = eventDestination(e);
  const providers = eventProviders(row), models = eventModels(row), status = eventStatus(row);
  const workload = e.workload?.workload_name ? e.workload : e.actor?.workload;
  const [copyState, setCopyState] = useState("");
  async function copy(value: string, label: string) {
    try { await navigator.clipboard.writeText(value); setCopyState(`${label} copied`); }
    catch { setCopyState("Copy unavailable. Select the field text to copy it."); }
  }
  const field = (label: string, value?: string | number | null, mono = false, required = false) => value !== undefined && value !== null && value !== "" || required ? <div key={label} className="flex items-start justify-between gap-4 border-b border-border/40 py-2.5 text-xs last:border-0">
    <dt className="shrink-0 pt-0.5 text-muted-foreground">{label}</dt>
    <dd className="flex min-w-0 items-start gap-2 text-right"><span className={`min-w-0 select-text break-words [overflow-wrap:anywhere] ${mono ? "font-mono text-[11px]" : "font-medium"}`}>{value ?? "Not reported"}</span>{value !== undefined && value !== null && value !== "" ? <button type="button" aria-label={`Copy ${label.toLowerCase()}`} title={`Copy ${label.toLowerCase()}`} className="shrink-0 rounded p-0.5 text-muted-foreground hover:bg-muted hover:text-foreground" onClick={() => void copy(String(value), label)}><Copy className="size-3.5"/></button> : null}</dd>
  </div> : null;
  return <>
    <div className="shrink-0 border-b border-border/80 bg-card/95 py-4 pl-5 pr-12">
      <DrawerTitle className="flex flex-wrap items-center gap-2.5"><span className="flex size-8 items-center justify-center rounded-lg border border-border bg-primary/10 text-primary"><Bot className="size-4"/></span><span className="text-sm font-bold">{providers[0] ?? destination ?? "AI activity"}{providers.length > 1 ? ` +${providers.length - 1}` : ""}</span><EventStatusBadge status={status}/></DrawerTitle>
      <DrawerDescription className="mt-2 text-xs">{eventActivity(row)} · {formatDateTime(e.observed_at)}</DrawerDescription>
    </div>
    <div className="custom-scrollbar min-h-0 flex-1 space-y-5 overflow-y-auto px-5 py-5">
      <section data-drawer-section="Overview" className="grid gap-3 sm:grid-cols-2" aria-label="Activity overview">
        <Summary icon={UserRound} label={e.inventory?.user_role ? eventLabel(e.inventory.user_role) : "Source identity"} value={person ?? "Not identified"} secondary={e.actor?.identity?.source_subject_kind === "source_user_id" && !e.actor.identity.email ? "Source user ID" : undefined}/>
        <Summary icon={Laptop} label="Endpoint" value={e.actor?.hostname ?? ips[0] ?? "Not reported"} secondary={e.actor?.hostname ? ips.join(" · ") : undefined}/>
        <Summary icon={Bot} label="AI provider / model" value={providers.join(", ") || "Provider not identified"} secondary={models.join(", ") || "Model not reported"}/>
        <Summary icon={Plug} label="Connector" value={row.connector} secondary={connectorTypeLabel(e.connector.connector_type)}/>
      </section>
      <Section title="Authorization">
        <p className={`text-sm font-semibold leading-relaxed ${status === "unsanctioned" ? "text-red-700 dark:text-red-400" : "text-foreground"}`}>{authorizationReason(row)}</p>
        <p className="mt-2 text-xs leading-relaxed text-muted-foreground">Current registry decisions. The source-reported action below describes what happened at the time of this event.</p>
        {row.findings.length ? <div className="mt-3 divide-y divide-border/50">{row.findings.map(f => <div key={f.finding_id} className="py-2.5 text-xs"><div className="flex items-center justify-between gap-3"><span className="font-semibold">{f.provider.name}{f.model ? ` / ${f.model.name}` : ""}</span><EventStatusBadge status={f.status}/></div><p className="mt-1.5 text-muted-foreground">Provider: {decision(f.provider.sanctioned)}{f.model ? ` · Model: ${decision(f.model.sanctioned)}` : ""}{f.model_version ? ` · Version: ${f.model_version}` : ""}</p></div>)}</div> : null}
      </Section>
      <Section title="Person & endpoint">
        {!person ? <p className="mb-2 text-xs leading-relaxed text-muted-foreground">This source did not identify a person. Use the hostname, source IP, or workload to investigate ownership.</p> : null}
        <dl>{field("Person", person, false, true)}{field("Source user ID", e.actor?.identity?.source_subject !== person ? e.actor?.identity?.source_subject : undefined)}{field("Identity source", e.actor?.identity?.authority ? eventLabel(e.actor.identity.authority) : undefined)}{field("Hostname", e.actor?.hostname, true, true)}{field("Source IP", ips.join(", ") || undefined, true, true)}{field("Device reference", e.actor?.device_key, true)}</dl>
        <div className="mt-3 flex flex-wrap gap-2">{person ? <Pivot label="Person activity" value={person} onInvestigate={onInvestigate}/> : null}{e.actor?.hostname || ips[0] ? <Pivot label="Endpoint activity" value={e.actor?.hostname ?? ips[0]} onInvestigate={onInvestigate}/> : null}</div>
      </Section>
      <Section title="Process & attribution">
        <dl>{field("Executable",e.process?.executable,true,true)}{field("Process ID",e.process?.pid,true)}{field("Native process ID",e.process?.unique_id,true)}{field("Process started",e.process?.started_at ? formatDateTime(e.process.started_at) : undefined)}{field("Parent executable",e.process?.parent_executable,true)}{field("Parent process ID",e.process?.parent_pid,true)}{field("Parent native ID",e.process?.parent_unique_id,true)}{field("User role",e.inventory?.user_role ? eventLabel(e.inventory.user_role) : "Source-reported association")}</dl>
        <p className="mt-2 text-xs text-muted-foreground">Client hints and assigned owners do not establish the initiating executable or request actor.</p>
      </Section>
      {row.findings[0] && <section data-drawer-section="Linked attribution"><FindingActivity findingId={row.findings[0].finding_id} observationId={e.observation_id}/></section>}
      <Section title="AI service & destination">
        <dl>{field("Provider", providers.join(", ") || undefined, false, true)}{field("Model", models.join(", ") || undefined, false, true)}{field("Reported model ID", e.service?.declared_model_id, true)}{field("Destination hostname", e.destination?.host ?? e.service?.tls_server_name, true, true)}{field("Destination IP", e.destination?.ip, true)}{field("Destination port", e.destination?.port ?? e.network?.destination_port)}{field("Service path", e.destination?.path_prefix, true)}{field("Application", e.service?.vendor_application_id)}</dl>
        {destination ? <div className="mt-3"><Pivot label="Destination activity" value={destination} onInvestigate={onInvestigate}/></div> : null}
      </Section>
      <Section title="Activity & evidence">
        <dl>{field("Activity", eventActivity(row))}{field("Observed", formatDateTime(e.observed_at))}{field("Received", formatDateTime(e.received_at))}{field("Connector", row.connector)}{field("Source action", e.outcome?.action ? eventLabel(e.outcome.action) : undefined, false, true)}{field("Source result", e.outcome?.result ? eventLabel(e.outcome.result) : undefined, false, true)}{field("Response code", e.outcome?.response_code)}{field("Client / framework", e.actor?.request_client?.name ? eventLabel(e.actor.request_client.name) : undefined)}{field("Source agent ID", e.actor?.request_client?.agent_id, true)}{field("Agent", e.agent?.name)}{field("Agent platform", e.agent?.platform)}{field("Process ID", e.agent?.process_id, true)}{field("Attribution", e.agent?.attribution_basis ? eventLabel(e.agent.attribution_basis) : undefined)}{field("Protocol", e.network?.protocol?.toUpperCase())}{field("Direction", e.network?.direction ? eventLabel(e.network.direction) : undefined)}{field("Bytes sent", e.network?.bytes_sent?.toLocaleString())}{field("Bytes received", e.network?.bytes_received?.toLocaleString())}{field("Request count", e.network?.request_count?.toLocaleString())}</dl>
        {["cloud_resource", "kubernetes_resource", "scan_fingerprint", "saas_capability", "network_mapping"].includes(e.kind) ? <p className="mt-3 rounded-lg bg-muted/50 p-3 text-xs leading-relaxed text-muted-foreground">This is discovery or configuration evidence. It does not by itself establish that a person made an AI request.</p> : null}
        {e.actor?.request_client?.name ? <p className="mt-2 text-xs text-muted-foreground">The client / framework is a source-reported hint.</p> : null}
      </Section>
      {e.cloud || workload?.workload_name || e.saas ? <Section title="Cloud & workload"><dl>{field("Cloud provider", e.cloud?.provider ? eventLabel(e.cloud.provider) : undefined)}{field("Cloud service", e.cloud?.provider_service ? eventLabel(e.cloud.provider_service) : undefined)}{field("Region", e.cloud?.region)}{field("Resource type", e.cloud?.resource_kind ? eventLabel(e.cloud.resource_kind) : undefined)}{field("Resource state", e.cloud?.lifecycle_state ? eventLabel(e.cloud.lifecycle_state) : undefined)}{field("Namespace", workload?.namespace_name, true)}{field("Workload", workload?.workload_name, true)}{field("Workload type", workload?.workload_kind ? eventLabel(workload.workload_kind) : undefined)}{field("Runtime image", workload?.runtime_image, true)}{field("Capability state", e.saas?.capability_state ? eventLabel(e.saas.capability_state) : undefined)}</dl></Section> : null}
      <Section title="Source references"><dl>{field("Event ID", e.observation_id, true)}{field("Source record ID", e.source?.source_record_id, true)}{field("Connector ID", e.connector.instance_id, true)}{field("Probe ID", e.source?.probe_id, true)}</dl></Section>
    </div>
    <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-border/80 bg-card px-5 py-3">
      <p role="status" className="text-xs text-muted-foreground">{copyState}</p>
      <Button size="sm" onClick={() => void copy(eventHandoff(row), "Investigation details")}>{copyState === "Investigation details copied" ? <Check className="size-3.5"/> : <Copy className="size-3.5"/>}Copy investigation details</Button>
    </div>
  </>;
}
const decision = (value: boolean | null) => value === null ? "Awaiting decision" : value ? "Sanctioned" : "Unsanctioned";
function Summary({ icon: Icon, label, value, secondary }: { icon: typeof Globe; label: string; value: string; secondary?: string }) {
  return <div className="flex min-w-0 items-start gap-3 rounded-xl border border-border/60 bg-card p-3.5 shadow-xs"><span className="flex size-8 shrink-0 items-center justify-center rounded-lg border border-border/45 bg-primary/5 text-primary"><Icon className="size-4"/></span><div className="min-w-0"><p className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">{label}</p><p className="mt-1 break-words text-xs font-semibold [overflow-wrap:anywhere]">{value}</p>{secondary ? <p className="mt-1 break-words text-[11px] text-muted-foreground [overflow-wrap:anywhere]">{secondary}</p> : null}</div></div>;
}
function Section({ title, children }: { title: string; children: ReactNode }) {
  return <details open data-drawer-section={title} className="group rounded-xl border border-border/60 bg-card/70 p-4 shadow-xs"><summary className="flex cursor-pointer items-center justify-between gap-2 text-[10px] font-bold uppercase tracking-wider text-muted-foreground"><span>{title}</span><ChevronDown className="size-3.5 transition-transform group-open:rotate-180"/></summary><div className="pt-3">{children}</div></details>;
}
function Pivot({ label, value, onInvestigate }: { label: string; value: string; onInvestigate: (query: string) => void }) {
  return <button type="button" onClick={() => onInvestigate(value)} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs font-medium text-primary hover:bg-muted">{label}<ArrowRight className="size-3"/></button>;
}
