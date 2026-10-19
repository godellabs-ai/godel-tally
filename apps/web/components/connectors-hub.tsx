"use client";

import * as React from "react";
import {
  AlertCircle,
  ArrowRight,
  CheckCircle2,
  Cloud,
  Network,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { getVendorFromIdentifier, VendorIcon } from "./vendor-icon";
import { ConnectorConfigModal } from "./connector-config-modal";
import { ScannerWorkspace } from "./scanner-workspace";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  deleteConnector,
  getTallyConnectors,
  getConnectorConfiguration,
  syncAllConnectors,
  syncConnector,
  type ConnectorJob,
  type ScanJob,
  type ConnectorState,
  type ConnectorStatesResponse,
} from "../lib/tally";
import {
  CONNECTOR_CATALOG,
  CONNECTOR_CATEGORIES,
  NATIVE_SCANNER_DEFINITION,
  connectorFriendlyName,
  type ConnectorCategoryId,
  type ConnectorSchemaId,
} from "../lib/connector-catalog";
import { cn } from "@/lib/utils";

type Notice = { kind: "info" | "error"; message: string };

interface ConnectorsHubProps {
  initialData: ConnectorStatesResponse | null;
  initialScans: ScanJob[];
  activeCategory?: ConnectorCategoryId;
  embedded?: boolean;
  onConfigOpen?: (schemaId: ConnectorSchemaId, connectorId: string | null) => void;
  renderConfigSetup?: (schemaId: ConnectorSchemaId) => React.ReactNode;
  configPermissionHelp?: (schemaId: ConnectorSchemaId) => { title: string; permissions: string[] } | undefined;
  onConfigured?: (schemaId: ConnectorSchemaId, connectorId: string) => Promise<void>;
}

const CATEGORY_ICONS = {
  "ai-platforms": Cloud,
  "ai-gateways": Network,
  "internet-security": ShieldCheck,
  infrastructure: ScanSearch,
} satisfies Record<ConnectorCategoryId, typeof Cloud>;

export function ConnectorsHub({
  initialData,
  initialScans,
  activeCategory,
  embedded = false,
  onConfigOpen,
  renderConfigSetup,
  configPermissionHelp,
  onConfigured,
}: ConnectorsHubProps) {
  const [liveItems, setLiveItems] = React.useState<ConnectorState[]>(
    initialData?.items ?? []
  );
  const [jobs, setJobs] = React.useState<ConnectorJob[]>(
    initialData?.jobs ?? []
  );
  const [syncingAll, setSyncingAll] = React.useState(false);
  const [deleting, setDeleting] = React.useState(false);
  const [notice, setNotice] = React.useState<Notice | null>(null);

  const [configModalOpen, setConfigModalOpen] = React.useState(false);
  const [configSchemaId, setConfigSchemaId] = React.useState<ConnectorSchemaId | null>(null);
  const [editConnectorId, setEditConnectorId] = React.useState<string | null>(null);
  const [editFriendlyName, setEditFriendlyName] = React.useState<string | null>(null);
  const [editConfiguration, setEditConfiguration] = React.useState<
    Record<string, string> | null | undefined
  >(undefined);
  const [connectorToDelete, setConnectorToDelete] = React.useState<string | null>(null);
  const [credentialReentryRequired, setCredentialReentryRequired] = React.useState(false);
  const configurationRequestId = React.useRef(0);

  const openConfig = (schemaId: ConnectorSchemaId, connector?: ConnectorState) => {
    const requestId = ++configurationRequestId.current;
    onConfigOpen?.(schemaId, connector?.connector_instance_id ?? null);
    setConfigSchemaId(schemaId);
    setEditConnectorId(connector?.connector_instance_id ?? null);
    setEditFriendlyName(connector?.friendly_name ?? null);
    setEditConfiguration(connector ? undefined : null);
    setCredentialReentryRequired(false);
    setConfigModalOpen(true);
    if (connector) {
      void getConnectorConfiguration(connector.connector_instance_id).then((configuration) => {
        if (configurationRequestId.current === requestId) {
          setEditConfiguration(configuration?.fields ?? null);
          setCredentialReentryRequired(Boolean(configuration?.credential_reentry_required));
        }
      });
    }
  };

  const activeConnectors: ConnectorState[] = React.useMemo(() => {
    return liveItems;
  }, [liveItems]);

  const refreshTimers = React.useRef<number[]>([]);
  React.useEffect(
    () => () => {
      refreshTimers.current.forEach(window.clearTimeout);
    },
    []
  );

  const refreshNow = React.useCallback(async () => {
    const data = await getTallyConnectors();
    if (!data) return;
    setLiveItems(data.items);
    setJobs(data.jobs);
  }, []);

  // Triggering a sync only brings the schedule due: the collector claims it on its next poll
  // (five seconds by default) and the run itself takes a little longer. Re-read a few times so
  // the cards land on the real outcome instead of leaving the page on a permanent poll.
  const trackQueuedRuns = React.useCallback(() => {
    refreshTimers.current.forEach(window.clearTimeout);
    refreshTimers.current = [3_000, 8_000, 15_000, 30_000].map((delay) =>
      window.setTimeout(() => {
        void refreshNow();
      }, delay)
    );
  }, [refreshNow]);

  async function handleSyncAll() {
    setSyncingAll(true);
    setNotice(null);
    const result = await syncAllConnectors();
    setSyncingAll(false);
    if (!result.ok) {
      setNotice({ kind: "error", message: result.error });
      return;
    }
    const { triggered, skipped_leased, skipped_paused } = result.data;
    const skipped = [
      skipped_leased > 0 ? `${skipped_leased} already running` : null,
      skipped_paused > 0 ? `${skipped_paused} paused` : null,
    ]
      .filter(Boolean)
      .join(" · ");
    setNotice({
      kind: "info",
      message:
        triggered === 0
          ? `No feed was queued${skipped ? ` — ${skipped}.` : "; nothing is scheduled yet."}`
          : `Queued ${triggered} feed${triggered === 1 ? "" : "s"}; the collector picks them up within seconds${skipped ? ` · skipped ${skipped}` : ""}.`,
    });
    await refreshNow();
    trackQueuedRuns();
  }

  async function handleSyncOne(connectorId: string) {
    setNotice(null);
    const result = await syncConnector(connectorId);
    if (result.ok) {
      await refreshNow();
      trackQueuedRuns();
    }
    return result;
  }

  async function handleDelete(connectorId: string) {
    setDeleting(true);
    setNotice(null);
    const result = await deleteConnector(connectorId);
    setDeleting(false);
    // Close the confirmation either way: the outcome is reported in the page banner, which the
    // dialog overlay would otherwise cover.
    setConnectorToDelete(null);
    if (!result.ok) {
      setNotice({ kind: "error", message: `Could not delete this connector: ${result.error}` });
      return;
    }
    setLiveItems((prev) => prev.filter((conn) => conn.connector_instance_id !== connectorId));
    setJobs((prev) => prev.filter((job) => job.connector_instance_id !== connectorId));
    if (editConnectorId === connectorId) {
      setEditConnectorId(null);
      setEditFriendlyName(null);
      setEditConfiguration(null);
    }
    setNotice({
      kind: "info",
      message: `Deleted ${connectorFriendlyName(result.data)} and ${result.data.runs_deleted} sync receipt${result.data.runs_deleted === 1 ? "" : "s"}. Existing findings remain, but this connector is no longer linked to them.`,
    });
    await refreshNow();
  }

  return (
    <div className="space-y-6">
      {notice && (
        <div
          className={cn(
            "flex items-start gap-2 rounded-xl border p-3 text-xs",
            notice.kind === "error"
              ? "border-destructive/40 bg-destructive/5 text-destructive"
              : "border-primary/30 bg-primary/5 text-foreground"
          )}
        >
          {notice.kind === "error" ? (
            <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
          ) : (
            <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-primary" />
          )}
          <p className="flex-1 leading-relaxed">{notice.message}</p>
          <button
            type="button"
            onClick={() => setNotice(null)}
            className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground hover:text-foreground"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Available integrations and the built-in scanner */}
      <div id="integration-catalog" className="space-y-4">
        {!embedded ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            {activeConnectors.some(connector => connector.sample) ? <p className="text-xs text-muted-foreground">Evaluation data is installed. Connect a source to collect live activity.</p> : <span />}
            <Button
              variant="outline"
              size="sm"
              onClick={() => void handleSyncAll()}
              disabled={syncingAll}
              className="h-8 gap-1.5 text-xs font-bold shadow-xs"
            >
              <RefreshCw className={`size-3.5 ${syncingAll ? "animate-spin" : ""}`} />
              {syncingAll ? "Syncing All Feeds..." : "Sync All Feeds"}
            </Button>
          </div>
        ) : null}

        <Tabs value={activeCategory} defaultValue="ai-platforms">
          {!embedded ? <TabsList className="flex h-auto w-full flex-wrap items-center justify-start gap-1 rounded-lg border border-border bg-card p-1 shadow-xs group-data-[orientation=horizontal]/tabs:h-auto">
            {CONNECTOR_CATEGORIES.map((category) => {
              const Icon = CATEGORY_ICONS[category.id];
              const count =
                CONNECTOR_CATALOG.filter((item) => item.category === category.id).length +
                (category.id === NATIVE_SCANNER_DEFINITION.category ? 1 : 0);
              return (
                <TabsTrigger
                  key={category.id}
                  value={category.id}
                  className="group h-auto flex-none gap-2 rounded-md px-3 py-1.5 text-sm font-bold text-muted-foreground transition-all hover:bg-muted hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-sm dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground"
                >
                  <Icon className="size-4 shrink-0 transition-transform duration-200 group-hover:scale-110" />
                  {category.label}
                  <span className="rounded-full bg-muted px-1.5 py-0.5 text-[10px] font-bold tabular-nums text-muted-foreground transition-colors group-data-[state=active]:bg-primary-foreground/20 group-data-[state=active]:text-primary-foreground">
                    {count}
                  </span>
                </TabsTrigger>
              );
            })}
          </TabsList> : null}

          {CONNECTOR_CATEGORIES.map((category) => {
            const items = CONNECTOR_CATALOG.filter((item) => item.category === category.id);
            return (
              <TabsContent
                key={category.id}
                value={category.id}
                className={cn("space-y-5", embedded ? "mt-0" : "mt-5")}
              >
                {!embedded ? <div>
                  <h3 className="text-sm font-bold text-foreground">{category.label}</h3>
                  <p className="mt-0.5 text-xs text-muted-foreground">{category.description}</p>
                </div> : null}

                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  {items.map((item) => {
                    const vendor = getVendorFromIdentifier(item.vendorIdentifier);
                    const matching = activeConnectors.filter(connector => item.connectorTypes.includes(connector.connector_type));
                    const configured = matching.filter(connector => !connector.sample);
                    const hasSamples = matching.some(connector => connector.sample);
                    const healthy = configured.some((connector) => connector.health === "healthy");
                    const needsAttention =
                      configured.length > 0 &&
                      configured.some((connector) => connector.health === "error");
                    const statusLabel = needsAttention
                      ? "Needs attention"
                      : healthy
                        ? "Connected"
                        : "Configured";
                    return (
                    <GlareCard
                      key={item.schemaId}
                      onClick={() => openConfig(item.schemaId, configured[0])}
                    >
                      <div className="flex items-start gap-3">
                        <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-white shadow-sm transition-transform duration-300 group-hover:scale-105">
                          <VendorIcon vendor={vendor} className="size-6" />
                        </span>
                        <div className="min-w-0">
                          <h3 className="font-semibold text-foreground transition-colors group-hover:text-primary">
                            {item.title}
                          </h3>
                          {configured.length > 0 ? (
                            <span
                              className={cn(
                                "inline-flex items-center gap-1.5 text-xs",
                                needsAttention
                                  ? "text-destructive"
                                  : healthy
                                    ? "text-emerald-600 dark:text-emerald-400"
                                    : "text-muted-foreground",
                              )}
                            >
                              <span
                                className={cn(
                                  "size-1.5 rounded-full",
                                  needsAttention
                                    ? "bg-destructive"
                                    : healthy
                                      ? "bg-emerald-500"
                                      : "bg-muted-foreground",
                                )}
                              />
                              {statusLabel}
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                              <Zap className="size-3" /> {hasSamples ? "Evaluation data available" : "Ready to connect"}
                            </span>
                          )}
                        </div>
                      </div>

                      <p className="mt-4 min-h-10 line-clamp-3 text-sm leading-relaxed text-muted-foreground">
                        {item.description}
                      </p>

                      <div className="mt-auto flex items-center justify-between border-t border-border/60 pt-4">
                        <span className="rounded-md border border-border bg-muted/60 px-2.5 py-1 text-[11px] font-medium text-muted-foreground">
                          {category.label}
                        </span>
                        {configured.length > 0 ? (
                          <span
                            className={cn(
                              "inline-flex items-center gap-1.5 text-xs font-medium",
                              needsAttention
                                ? "text-destructive"
                                : "text-emerald-600 dark:text-emerald-400",
                            )}
                          >
                            {needsAttention ? (
                              <AlertCircle className="size-3.5" />
                            ) : (
                              <CheckCircle2 className="size-3.5" />
                            )}
                            {configured.length.toLocaleString()} configured
                          </span>
                        ) : (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="font-medium text-primary hover:text-primary"
                            onClick={(event) => {
                              event.stopPropagation();
                              openConfig(item.schemaId);
                            }}
                          >
                            Connect <ArrowRight className="size-4" />
                          </Button>
                        )}
                      </div>
                    </GlareCard>
                    );
                  })}

                  {category.id === NATIVE_SCANNER_DEFINITION.category ? (
                    <GlareCard>
                      <div className="flex items-start gap-3">
                        <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-border bg-white shadow-sm transition-transform duration-300 group-hover:scale-105">
                          <VendorIcon
                            vendor={getVendorFromIdentifier(NATIVE_SCANNER_DEFINITION.vendorIdentifier)}
                            className="size-6"
                          />
                        </span>
                        <div>
                          <h3 className="font-semibold text-foreground">
                            {NATIVE_SCANNER_DEFINITION.title}
                          </h3>
                          <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
                            <ScanSearch className="size-3" /> Built into Tally
                          </span>
                        </div>
                      </div>
                      <p className="mt-4 min-h-10 text-sm leading-relaxed text-muted-foreground">
                        {NATIVE_SCANNER_DEFINITION.description}
                      </p>
                      <div className="mt-auto flex items-center justify-between border-t border-border/60 pt-4">
                        <span className="rounded-md border border-border bg-muted/60 px-2.5 py-1 text-[11px] font-medium text-muted-foreground">
                          {category.label}
                        </span>
                        <Badge variant="secondary" className="text-[10px]">Built in</Badge>
                      </div>
                    </GlareCard>
                  ) : null}
                </div>

                {category.id === NATIVE_SCANNER_DEFINITION.category && (
                  <section className="space-y-5 border-t border-border pt-5">
                    <ScannerWorkspace initialJobs={initialScans} />
                  </section>
                )}
              </TabsContent>
            );
          })}
        </Tabs>
      </div>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={!!connectorToDelete}
        onOpenChange={(open) => {
          if (!open && !deleting) setConnectorToDelete(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Connector</DialogTitle>
            <DialogDescription>
              This permanently removes the connector&apos;s configuration, credentials, history, and
              links from findings. Existing provider and model findings remain until you remove them
              from Settings.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              disabled={deleting}
              onClick={() => setConnectorToDelete(null)}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={deleting}
              onClick={() => {
                if (connectorToDelete) void handleDelete(connectorToDelete);
              }}
            >
              {deleting ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Configuration Modal */}
      <ConnectorConfigModal
        open={configModalOpen}
        onOpenChange={setConfigModalOpen}
        schemaId={configSchemaId}
        setupContent={configSchemaId ? renderConfigSetup?.(configSchemaId) : undefined}
        permissionsOverride={configSchemaId ? configPermissionHelp?.(configSchemaId)?.permissions : undefined}
        permissionTitle={configSchemaId ? configPermissionHelp?.(configSchemaId)?.title : undefined}
        onConfigured={configSchemaId && onConfigured ? (connectorId) => onConfigured(configSchemaId, connectorId) : undefined}
        existingConnectorId={editConnectorId}
        existingFriendlyName={editFriendlyName}
        existingConfiguration={editConfiguration}
        credentialReentryRequired={credentialReentryRequired}
        configuredConnectors={
          configSchemaId
            ? activeConnectors.filter((connector) =>
                !connector.sample && CONNECTOR_CATALOG.find((item) => item.schemaId === configSchemaId)?.connectorTypes.includes(
                  connector.connector_type,
                ),
              )
            : []
        }
        jobs={jobs}
        onSelectConnector={(connector) => {
          if (configSchemaId) openConfig(configSchemaId, connector);
        }}
        onNewConnector={() => {
          if (configSchemaId) openConfig(configSchemaId);
        }}
        onSyncConnector={handleSyncOne}
        onDeleteConnector={(connectorId) => setConnectorToDelete(connectorId)}
        onSuccess={() => {
          void refreshNow();
        }}
      />
    </div>
  );
}

function GlareCard({
  children,
  className,
  onClick,
}: {
  children: React.ReactNode;
  className?: string;
  onClick?: (e: React.MouseEvent<HTMLDivElement>) => void;
}) {
  return (
    <div
      onClick={onClick}
      className={cn(
        "card-surface group relative flex flex-col overflow-hidden p-5",
        onClick && "card-surface-hover cursor-pointer",
        className
      )}
    >
      <div className="card-glare-shine-wrapper">
        <div className="card-glare-shine" />
      </div>

      <div className="relative z-10 flex h-full flex-col justify-between">
        {children}
      </div>
    </div>
  );
}
