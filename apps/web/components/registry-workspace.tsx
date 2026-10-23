"use client";

import {
  Brain,
  Briefcase,
  Check,
  Cloud,
  Cpu,
  ImageIcon,
  LoaderCircle,
  Network,
  Server,
  SlidersHorizontal,
  Terminal,
  X,
  type LucideIcon,
} from "lucide-react";
import { useMemo, useState, type ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { CustomTable, type Column } from "@/components/ui/custom-table";
import { SearchableDropdown } from "@/components/ui/searchable-dropdown";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import {
  setRegistrySanction,
  type RegistryModel,
  type RegistryProvider,
} from "../lib/tally";

type SanctionFilter = "all" | "sanctioned" | "unsanctioned" | "undecided";
type ProviderCategory = RegistryProvider["category"];
type RegistryTab = string;

export interface RegistryWorkspaceExtension {
  value: string;
  label: string;
  content: ReactNode;
}

const PROVIDER_TABS: Array<{
  value: ProviderCategory;
  label: string;
  icon: LucideIcon;
}> = [
  { value: "direct_provider", label: "Direct providers", icon: Cpu },
  { value: "enterprise_application", label: "Enterprise apps", icon: Briefcase },
  { value: "managed_platform", label: "Managed AI", icon: Cloud },
  { value: "ai_gateway", label: "AI gateways", icon: Network },
  { value: "local_runtime", label: "Local AI", icon: Terminal },
  { value: "inference_server", label: "Inference servers", icon: Server },
];

const SANCTION_OPTIONS = [
  { value: "all", label: "All sanction statuses" },
  { value: "sanctioned", label: "Sanctioned" },
  { value: "unsanctioned", label: "Unsanctioned" },
  { value: "undecided", label: "Needs sanction decision" },
];

const CAPABILITY_OPTIONS = [
  { value: "all", label: "All capabilities" },
  { value: "image_generation", label: "Image generation" },
  { value: "video_generation", label: "Video generation" },
  { value: "coding", label: "Coding" },
  { value: "embeddings", label: "Embeddings" },
  { value: "reasoning", label: "Reasoning" },
];

export function RegistryWorkspace({
  initialProviders,
  initialModels,
  providerDomains,
  canWrite = true,
  onChanged,
  extensions = [],
  enforcementAvailable = false,
}: {
  initialProviders: RegistryProvider[];
  initialModels: RegistryModel[];
  /** Reviewed hostnames, keyed by provider key. */
  providerDomains?: Record<string, string[]>;
  canWrite?: boolean;
  /** Set by hosts such as Gödel Gate that can block requests; standalone Tally only records decisions. */
  enforcementAvailable?: boolean;
  onChanged?: () => void;
  /** Host-owned registry sections. Standalone Tally supplies none. */
  extensions?: RegistryWorkspaceExtension[];
}) {
  const [providers, setProviders] = useState(initialProviders);
  const [models, setModels] = useState(initialModels);
  const [tab, setTab] = useState<RegistryTab>("direct_provider");
  const [query, setQuery] = useState("");
  const [sanctionFilter, setSanctionFilter] = useState<SanctionFilter>("all");
  const [capability, setCapability] = useState("all");
  const [selected, setSelected] = useState<Set<string | number>>(new Set());
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const extensionValues = useMemo(
    () => new Set(extensions.map((extension) => extension.value)),
    [extensions],
  );

  // Pagination states
  const [providerPage, setProviderPage] = useState(1);
  const [providerPageSize, setProviderPageSize] = useState(50);
  const [modelPage, setModelPage] = useState(1);
  const [modelPageSize, setModelPageSize] = useState(50);

  // Sorting
  const [sortKey, setSortKey] = useState<string | null>("name");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  // Filtered providers
  const filteredProviders = useMemo(() => {
    return providers.filter((item) => {
      const matchesQuery = `${item.name} ${item.key} ${(providerDomains?.[item.key] ?? []).join(" ")}`
        .toLowerCase()
        .includes(query.toLowerCase());
      return (
        matchesQuery &&
        matchesSanction(item.sanctioned, sanctionFilter) &&
        item.category === tab
      );
    });
  }, [providers, providerDomains, query, sanctionFilter, tab]);

  // Sorted providers
  const sortedProviders = useMemo(() => {
    if (!sortKey) return filteredProviders;
    return [...filteredProviders].sort((a, b) => {
      let comparison = 0;
      if (sortKey === "name") comparison = a.name.localeCompare(b.name);
      else if (sortKey === "category") comparison = a.category.localeCompare(b.category);
      else if (sortKey === "models") comparison = a.model_count - b.model_count;
      else if (sortKey === "findings") comparison = a.finding_count - b.finding_count;
      return sortDir === "asc" ? comparison : -comparison;
    });
  }, [filteredProviders, sortKey, sortDir]);

  // Paginated providers
  const paginatedProviders = useMemo(() => {
    const start = (providerPage - 1) * providerPageSize;
    return sortedProviders.slice(start, start + providerPageSize);
  }, [sortedProviders, providerPage, providerPageSize]);

  // Filtered models
  const filteredModels = useMemo(() => {
    return models.filter((item) => {
      const matchesQuery = `${item.name} ${item.family} ${item.key} ${item.provider_names.join(" ")}`.toLowerCase().includes(query.toLowerCase());
      return matchesQuery && matchesSanction(item.sanctioned, sanctionFilter) && (capability === "all" || item.capabilities.includes(capability));
    });
  }, [models, query, sanctionFilter, capability]);

  // Sorted models
  const sortedModels = useMemo(() => {
    if (!sortKey) return filteredModels;
    return [...filteredModels].sort((a, b) => {
      let comparison = 0;
      if (sortKey === "name") comparison = a.name.localeCompare(b.name);
      else if (sortKey === "family") comparison = a.family.localeCompare(b.family);
      else if (sortKey === "findings") comparison = a.finding_count - b.finding_count;
      return sortDir === "asc" ? comparison : -comparison;
    });
  }, [filteredModels, sortKey, sortDir]);

  // Paginated models
  const paginatedModels = useMemo(() => {
    const start = (modelPage - 1) * modelPageSize;
    return sortedModels.slice(start, start + modelPageSize);
  }, [sortedModels, modelPage, modelPageSize]);

  function changeTab(value: string) {
    const next = value as RegistryTab;
    setTab(next);
    setSelected(new Set());
    setCapability("all");
    setQuery("");
    setProviderPage(1);
    setModelPage(1);
  }

  async function apply(ids: string[], sanctioned: boolean) {
    if (!canWrite || !ids.length) return;
    setPending(true);
    setNotice(null);
    const kind = tab === "models" ? "model" : "provider";
    const result = await setRegistrySanction(kind, ids, sanctioned);
    setPending(false);
    if (!result.ok) {
      setNotice(result.error);
      return;
    }
    if (kind === "provider") {
      setProviders((rows) => rows.map((item) => ids.includes(item.provider_id) ? { ...item, sanctioned } : item));
    } else {
      setModels((rows) => rows.map((item) => ids.includes(item.model_id) ? { ...item, sanctioned } : item));
    }
    setSelected(new Set());
    setNotice(`${result.data.affected} ${kind}${result.data.affected === 1 ? "" : "s"} ${sanctioned ? "sanctioned" : "unsanctioned"}.`);
    onChanged?.();
  }

  const selectedList = useMemo(() => Array.from(selected).map(String), [selected]);

  // Provider columns
  const providerColumns: Column<RegistryProvider>[] = [
    {
      header: "Provider",
      sortKey: "name",
      cell: (p) => {
        const domains = providerDomains?.[p.key] ?? [];
        return (
          <div className="min-w-0">
            <p className="truncate text-sm font-bold text-foreground">{p.name}</p>
            {domains.length > 0 ? (
              <TooltipProvider delayDuration={150}>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <button type="button" className="block w-64 max-w-full truncate text-left text-[10px] text-muted-foreground">
                      {domains.join(", ")}
                    </button>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="max-w-sm whitespace-normal">
                    <div className="max-h-64 space-y-1 overflow-y-auto">
                      {domains.map((domain) => <div key={domain} className="break-all">{domain}</div>)}
                    </div>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            ) : null}
          </div>
        );
      },
    },
    {
      header: "Type",
      sortKey: "category",
      cell: (p) => (
        <span className="inline-flex rounded-md bg-muted/60 px-2 py-0.5 text-xs font-semibold capitalize text-muted-foreground">
          {categoryLabel(p.category)}
        </span>
      ),
    },
    ...(providerDomains ? [{
      header: "Connector domains",
      className: "w-[180px]",
      cell: (p: RegistryProvider) => {
        const count = providerDomains[p.key]?.length ?? 0;
        return (
          <span
            className="text-xs font-medium text-muted-foreground"
            title={count > 0
              ? "Mapped domains can be blocked by enabled enforcement connectors."
              : "No connector domain is mapped. Identified requests can still be governed by an active runtime policy."}
          >
            {count > 0 ? `${count} mapped` : "None mapped"}
          </span>
        );
      },
    } satisfies Column<RegistryProvider>] : []),
    {
      header: "Models",
      sortKey: "models",
      cell: (p) => (
        <span className="font-mono text-xs font-bold tabular-nums text-foreground">
          {p.model_count}
        </span>
      ),
    },
    {
      header: "Observed",
      sortKey: "findings",
      cell: (p) => (
        <span className="font-mono text-xs font-bold tabular-nums text-foreground">
          {p.finding_count}
        </span>
      ),
    },
    {
      header: "Registry decision",
      className: "w-[190px] text-right",
      cell: (p) => (
        <div className="flex justify-end">
          <SanctionSwitch
            sanctioned={p.sanctioned}
            pending={pending}
            readOnly={!canWrite}
            onChange={(sanctioned) => void apply([p.provider_id], sanctioned)}
          />
        </div>
      ),
    },
  ];

  // Model columns
  const modelColumns: Column<RegistryModel>[] = [
    {
      header: "Model",
      sortKey: "name",
      cell: (m) => (
        <div className="min-w-0">
          <p className="truncate text-sm font-bold text-foreground">{m.name}</p>
          <p className="truncate text-[10px] text-muted-foreground">{m.family}</p>
        </div>
      ),
    },
    {
      header: "Providers",
      cell: (m) => (
        <span className="truncate text-xs font-medium text-muted-foreground" title={m.provider_names.join(", ")}>
          {providerSummary(m.provider_names)}
        </span>
      ),
    },
    {
      header: "Capabilities",
      cell: (m) => (
        <div className="flex min-w-0 flex-wrap gap-1">
          {m.capabilities.slice(0, 2).map((item) => (
            <span key={item} className="rounded-md bg-muted/60 px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground">
              {item === "image_generation" ? <ImageIcon className="mr-1 inline size-3" /> : null}
              {item.replaceAll("_", " ")}
            </span>
          ))}
        </div>
      ),
    },
    {
      header: "Observed",
      sortKey: "findings",
      cell: (m) => (
        <span className="font-mono text-xs font-bold tabular-nums text-foreground">
          {m.finding_count}
        </span>
      ),
    },
    {
      header: "Sanction Status",
      className: "w-[190px] text-right",
      cell: (m) => (
        <div className="flex justify-end">
          <SanctionSwitch
            sanctioned={m.sanctioned}
            pending={pending}
            readOnly={!canWrite}
            onChange={(sanctioned) => void apply([m.model_id], sanctioned)}
          />
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <Tabs value={tab} onValueChange={changeTab}>
        <div className="w-full overflow-x-auto scrollbar-hide">
          <TabsList className="flex h-auto w-full min-w-max flex-nowrap items-center justify-start gap-1 rounded-lg border border-border/80 bg-card p-1 shadow-2xs group-data-[orientation=horizontal]/tabs:h-auto">
            {PROVIDER_TABS.filter((item) => providers.some((provider) => provider.category === item.value)).map((item) => {
              const Icon = item.icon;
              return (
                <TabsTrigger
                  key={item.value}
                  value={item.value}
                  className="group h-auto flex-none shrink-0 whitespace-nowrap gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-semibold text-muted-foreground transition-all duration-150 hover:bg-muted/70 hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-xs dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground cursor-pointer"
                >
                  <Icon className="size-3.5 shrink-0 transition-transform duration-150 group-hover:scale-105" />
                  <span>{item.label}</span>
                  <Count
                    value={
                      providers.filter(
                        (provider) => provider.category === item.value
                      ).length
                    }
                  />
                </TabsTrigger>
              );
            })}
            <TabsTrigger
              value="models"
              className="group h-auto flex-none shrink-0 whitespace-nowrap gap-1.5 rounded-md px-3.5 py-1.5 text-xs font-semibold text-muted-foreground transition-all duration-150 hover:bg-muted/70 hover:text-foreground data-[state=active]:bg-primary data-[state=active]:text-primary-foreground data-[state=active]:shadow-xs dark:data-[state=active]:border-transparent dark:data-[state=active]:bg-primary dark:data-[state=active]:text-primary-foreground cursor-pointer"
            >
              <Brain className="size-3.5 shrink-0 transition-transform duration-150 group-hover:scale-105" />
              <span>AI Models</span>
              <Count value={models.length} />
            </TabsTrigger>
            {extensions.map((extension) => (
              <TabsTrigger key={extension.value} value={extension.value} className="px-3.5 text-xs font-semibold">
                {extension.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        <p className="mt-3 text-xs leading-relaxed text-muted-foreground">
          Providers and models start unsanctioned, except for the enterprise provider defaults.
          Sanction decisions can be changed below.
        </p>

        {/* Action Notice */}
        {notice ? (
          <div role="status" className="mt-4 rounded-xl border border-border bg-muted/20 px-4 py-2.5 text-xs text-muted-foreground">
            {notice}
          </div>
        ) : null}

        {/* Provider Category Table */}
        {extensions.map((extension) => (
          <TabsContent key={extension.value} value={extension.value} className="mt-4">
            {extension.content}
          </TabsContent>
        ))}
        {tab !== "models" && !extensionValues.has(tab) ? (
          <TabsContent value={tab} className="mt-4">
            {providerDomains ? (
              <p role="note" className="mb-3 rounded-lg border border-border bg-muted/25 px-4 py-3 text-xs leading-relaxed text-muted-foreground">
                {enforcementAvailable ? <>
                  These providers have reviewed AI service domains. A provider decision classifies
                  matching Tally findings; an active runtime policy can block identified requests.
                  Domain blocking requires an enabled enforcement connector and covers the mapped
                  domains shown below. Some regional or app-embedded endpoints may need additional mappings.
                </> : <>
                  These providers have reviewed AI service domains. A provider decision classifies
                  matching Tally findings as sanctioned or unsanctioned. Tally records the decision;
                  it does not block traffic. Some regional or app-embedded endpoints may need
                  additional mappings.
                </>}
              </p>
            ) : null}
            <CustomTable
              data={paginatedProviders}
              columns={providerColumns}
              keyExtractor={(p) => p.provider_id}
              selectionLabel={(p) => `Select ${p.name}`}
              selectedKeys={canWrite ? selected : undefined}
              onSelectionChange={canWrite ? setSelected : undefined}
              searchPlaceholder="Search providers by name or domain..."
              searchValue={query}
              onSearchChange={(val) => {
                setQuery(val);
                setProviderPage(1);
              }}
              sortKey={sortKey}
              sortDir={sortDir}
              onSort={handleSort}
              currentPage={providerPage}
              totalPages={Math.max(1, Math.ceil(sortedProviders.length / providerPageSize))}
              onPageChange={setProviderPage}
              pageSize={providerPageSize}
              onPageSizeChange={(sz) => {
                setProviderPageSize(sz);
                setProviderPage(1);
              }}
              totalItemsCount={sortedProviders.length}
              itemsName="providers"
              emptyStateTitle={`No ${categoryLabel(tab as ProviderCategory).toLowerCase()} matching the filter criteria`}
              emptyStateDescription="Try adjusting your search query or sanction status."
              filters={
                canWrite && selected.size > 0 ? (
                  <div className="flex flex-1 items-center justify-between gap-3">
                    <span className="text-xs font-bold text-primary">{selected.size} providers selected</span>
                    <div className="flex items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={pending}
                        onClick={() => void apply(selectedList, true)}
                        className="h-8 gap-1.5 text-xs font-bold text-emerald-600 dark:text-emerald-400"
                      >
                        <Check className="size-3.5" /> Sanction selected
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={pending}
                        onClick={() => void apply(selectedList, false)}
                        className="h-8 gap-1.5 text-xs font-bold text-red-600 dark:text-red-400"
                      >
                        <X className="size-3.5" /> Unsanction selected
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="w-48">
                      <SearchableDropdown
                        options={SANCTION_OPTIONS}
                        value={sanctionFilter}
                        onChange={(val) => {
                          setSanctionFilter(val as SanctionFilter);
                          setProviderPage(1);
                        }}
                        placeholder="Sanction status"
                      />
                    </div>
                    {(query || sanctionFilter !== "all") && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setQuery("");
                          setSanctionFilter("all");
                          setProviderPage(1);
                        }}
                        className="h-8.5 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                      >
                        <SlidersHorizontal className="size-3" /> Reset
                      </Button>
                    )}
                  </div>
                )
              }
            />
          </TabsContent>
        ) : null}

        {/* Models Table */}
        <TabsContent value="models" className="mt-4">
          <CustomTable
            data={paginatedModels}
            columns={modelColumns}
            keyExtractor={(m) => m.model_id}
            selectionLabel={(m) => `Select ${m.name}`}
            selectedKeys={canWrite ? selected : undefined}
            onSelectionChange={canWrite ? setSelected : undefined}
            searchPlaceholder="Search models by name, family, key, or provider..."
            searchValue={query}
            onSearchChange={(val) => {
              setQuery(val);
              setModelPage(1);
            }}
            sortKey={sortKey}
            sortDir={sortDir}
            onSort={handleSort}
            currentPage={modelPage}
            totalPages={Math.max(1, Math.ceil(sortedModels.length / modelPageSize))}
            onPageChange={setModelPage}
            pageSize={modelPageSize}
            onPageSizeChange={(sz) => {
              setModelPageSize(sz);
              setModelPage(1);
            }}
            totalItemsCount={sortedModels.length}
            itemsName="models"
            emptyStateTitle="No AI models matching the filter criteria"
            emptyStateDescription="Try adjusting your search query, capabilities filter, or sanction status."
            filters={
              canWrite && selected.size > 0 ? (
                <div className="flex flex-1 items-center justify-between gap-3">
                  <span className="text-xs font-bold text-primary">{selected.size} models selected</span>
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={pending}
                      onClick={() => void apply(selectedList, true)}
                      className="h-8 gap-1.5 text-xs font-bold text-emerald-600 dark:text-emerald-400"
                    >
                      <Check className="size-3.5" /> Sanction selected
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={pending}
                      onClick={() => void apply(selectedList, false)}
                      className="h-8 gap-1.5 text-xs font-bold text-red-600 dark:text-red-400"
                    >
                      <X className="size-3.5" /> Unsanction selected
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <div className="w-48">
                    <SearchableDropdown
                      options={SANCTION_OPTIONS}
                      value={sanctionFilter}
                      onChange={(val) => {
                        setSanctionFilter(val as SanctionFilter);
                        setModelPage(1);
                      }}
                      placeholder="Sanction status"
                    />
                  </div>
                  <div className="w-44">
                    <SearchableDropdown
                      options={CAPABILITY_OPTIONS}
                      value={capability}
                      onChange={(val) => {
                        setCapability(val);
                        setModelPage(1);
                      }}
                      placeholder="Capability"
                    />
                  </div>
                  {(query || sanctionFilter !== "all" || capability !== "all") && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setQuery("");
                        setSanctionFilter("all");
                        setCapability("all");
                        setModelPage(1);
                      }}
                      className="h-8.5 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                    >
                      <SlidersHorizontal className="size-3" /> Reset
                    </Button>
                  )}
                </div>
              )
            }
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function SanctionSwitch({
  sanctioned,
  pending,
  readOnly,
  onChange,
}: {
  sanctioned: boolean | null;
  pending: boolean;
  readOnly: boolean;
  onChange: (value: boolean) => void;
}) {
  return (
    <div className="flex min-w-[160px] items-center justify-end gap-2">
      {!readOnly ? (
        <Switch
          checked={sanctioned === true}
          disabled={pending}
          onCheckedChange={onChange}
          aria-label={`Mark ${sanctioned === true ? "unsanctioned" : "sanctioned"}`}
        />
      ) : null}
      <Badge
        variant={sanctioned === true ? "success" : sanctioned === false ? "destructive" : "warning"}
        className="min-w-[92px] justify-center"
      >
        {pending ? <LoaderCircle className="size-3 animate-spin" /> : sanctioned === true ? "Sanctioned" : sanctioned === false ? "Unsanctioned" : "Undecided"}
      </Badge>
    </div>
  );
}

function Count({ value }: { value: number }) {
  return (
    <span className="rounded-full px-2 py-0.5 text-[10px] font-bold tabular-nums transition-colors group-data-[state=active]:bg-primary-foreground group-data-[state=active]:text-primary bg-muted text-muted-foreground">
      {value}
    </span>
  );
}

function categoryLabel(category: ProviderCategory) {
  return (
    PROVIDER_TABS.find((item) => item.value === category)?.label ??
    category.replaceAll("_", " ")
  );
}

function providerSummary(names: string[]) {
  if (!names.length) return "Not available";
  if (names.length <= 2) return names.join(", ");
  return `${names.slice(0, 2).join(", ")} +${names.length - 2}`;
}

function matchesSanction(value: boolean | null, filter: SanctionFilter) {
  return (
    filter === "all" ||
    (filter === "sanctioned" && value === true) ||
    (filter === "unsanctioned" && value === false) ||
    (filter === "undecided" && value === null)
  );
}
