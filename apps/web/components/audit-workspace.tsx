"use client";

import * as React from "react";
import {
  CheckCircle2,
  ClipboardClock,
  Copy,
  Search,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Pagination } from "@/components/ui/pagination";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import type { AuditEvent } from "../lib/tally";
import { formatDateTime } from "../lib/datetime";

interface AuditWorkspaceProps {
  events: AuditEvent[];
}

export function AuditWorkspace({ events }: AuditWorkspaceProps) {
  const [query, setQuery] = React.useState("");
  const [currentPage, setCurrentPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(10);
  const [selectedEvent, setSelectedEvent] = React.useState<AuditEvent | null>(null);
  const [sheetOpen, setSheetOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return events;
    return events.filter((e) => {
      const haystack = [
        e.action,
        e.actor,
        e.entity_type,
        e.entity_id,
        JSON.stringify(e.detail),
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(q);
    });
  }, [events, query]);

  const totalPages = Math.ceil(filtered.length / pageSize);
  const paginated = React.useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, currentPage, pageSize]);

  function handleRowClick(e: AuditEvent) {
    setSelectedEvent(e);
    setSheetOpen(true);
  }

  function copyJson() {
    if (!selectedEvent) return;
    navigator.clipboard.writeText(JSON.stringify(selectedEvent, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-6">

      <div className="flex items-center gap-3 rounded-xl border border-border bg-card p-3 shadow-xs">
        <label className="flex h-9 min-w-64 flex-1 items-center gap-2 rounded-lg border border-border bg-background px-3 text-xs text-muted-foreground focus-within:ring-1 focus-within:ring-ring">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setCurrentPage(1);
            }}
            placeholder="Search action, actor, entity ID, audit receipt..."
            className="w-full bg-transparent outline-none text-foreground"
          />
        </label>
      </div>

      {/* Audit Table */}
      <div className="rounded-xl border border-border bg-card shadow-xs overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-[280px]">Action & Lifecycle</TableHead>
              <TableHead>Target Entity</TableHead>
              <TableHead>Actor Identity</TableHead>
              <TableHead>Event Detail Metadata</TableHead>
              <TableHead className="text-right">Timestamp</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginated.map((event) => (
              <TableRow
                key={event.audit_id}
                onClick={() => handleRowClick(event)}
                className="group transition-colors"
              >
                <TableCell className="font-semibold">
                  <div className="flex items-center gap-2.5">
                    <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-primary/10 text-primary">
                      {event.action.includes("authorization") ? (
                        <ShieldCheck className="size-4" />
                      ) : (
                        <ClipboardClock className="size-4" />
                      )}
                    </span>
                    <div>
                      <span className="font-bold text-xs text-foreground group-hover:text-primary transition-colors">
                        {label(event.action)}
                      </span>
                      <p className="text-[10px] font-mono text-muted-foreground">
                        {event.audit_id.slice(0, 14)}...
                      </p>
                    </div>
                  </div>
                </TableCell>

                <TableCell>
                  <span className="font-mono text-xs text-foreground font-semibold">
                    {event.entity_type}
                  </span>
                  <p className="text-[10px] font-mono text-muted-foreground truncate max-w-[150px]">
                    {event.entity_id}
                  </p>
                </TableCell>

                <TableCell>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {event.actor}
                  </Badge>
                </TableCell>

                <TableCell className="text-xs text-muted-foreground truncate max-w-[300px]">
                  {summarizeDetail(event.detail)}
                </TableCell>

                <TableCell className="text-right font-mono text-xs text-muted-foreground">
                  {event.at ? formatDateTime(event.at) : "N/A"}
                </TableCell>
              </TableRow>
            ))}

            {paginated.length === 0 && (
              <TableRow>
                <TableCell
                  colSpan={5}
                  className="py-16 text-center text-muted-foreground text-sm"
                >
                  No auditable events recorded yet.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>

        {/* Pagination Footer */}
        <Pagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalItems={filtered.length}
          pageSize={pageSize}
          onPageChange={setCurrentPage}
          onPageSizeChange={(size) => {
            setPageSize(size);
            setCurrentPage(1);
          }}
        />
      </div>

      {/* Slide-over Inspection Sheet */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent side="right" className="space-y-6">
          <SheetHeader>
            <div className="flex items-center gap-2 mb-1">
              <Badge variant="outline" className="font-mono text-[10px]">
                Audit Receipt
              </Badge>
            </div>
            <SheetTitle className="text-lg font-bold tracking-tight text-foreground">
              {selectedEvent ? label(selectedEvent.action) : "Audit Event"}
            </SheetTitle>
            <SheetDescription className="font-mono text-[11px] text-muted-foreground">
              {selectedEvent ? formatDateTime(selectedEvent.at) : ""}
            </SheetDescription>
          </SheetHeader>

          {selectedEvent && (
            <div className="space-y-4">
              <div className="rounded-xl border border-border bg-card divide-y divide-border/50 text-xs">
                <div className="flex items-center justify-between p-3">
                  <span className="text-muted-foreground">Audit ID</span>
                  <span className="font-mono text-[10px] text-foreground">{selectedEvent.audit_id}</span>
                </div>
                <div className="flex items-center justify-between p-3">
                  <span className="text-muted-foreground">Actor</span>
                  <span className="font-mono font-semibold">{selectedEvent.actor}</span>
                </div>
                <div className="flex items-center justify-between p-3">
                  <span className="text-muted-foreground">Target Entity</span>
                  <span className="font-semibold">{selectedEvent.entity_type} : {selectedEvent.entity_id}</span>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                    Structured Detail Payload
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={copyJson}
                    className="h-7 text-[11px] gap-1"
                  >
                    {copied ? <CheckCircle2 className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
                    {copied ? "Copied" : "Copy JSON"}
                  </Button>
                </div>
                <pre className="custom-scrollbar max-h-64 overflow-auto rounded-xl border border-border bg-muted/40 p-3 font-mono text-[11px] text-foreground leading-relaxed">
                  {JSON.stringify(selectedEvent.detail, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function summarizeDetail(detail: Record<string, unknown>) {
  if (!detail) return "No metadata";
  const entries = Object.entries(detail).slice(0, 3);
  if (entries.length === 0) return "No additional metadata";
  return entries.map(([k, v]) => `${label(k)}: ${String(v)}`).join(" · ");
}

function label(value: string) {
  return value.replaceAll(/[._]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}
