"use client";

import React from "react";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Search,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { EmptyState } from "@/components/ui/empty-state";

export interface Column<T> {
  header: React.ReactNode;
  cell: (item: T) => React.ReactNode;
  className?: string;
  sortKey?: string;
}

interface CustomTableProps<T> {
  icon?: React.ReactNode;
  title?: string;
  subtitle?: React.ReactNode;
  data: T[];
  columns: Column<T>[];
  keyExtractor: (item: T) => string | number;
  
  // Search
  searchPlaceholder?: string;
  searchValue?: string;
  onSearchChange?: (val: string) => void;
  
  // Filters
  filters?: React.ReactNode;

  // Sorting
  sortKey?: string | null;
  sortDir?: "asc" | "desc";
  onSort?: (key: string) => void;

  // Pagination
  currentPage?: number;
  totalPages?: number;
  onPageChange?: (page: number) => void;
  pageSize?: number;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
  totalItemsCount?: number;
  itemsName?: string;
  onRowClick?: (item: T) => void;
  onPrevPage?: () => void;
  onNextPage?: () => void;
  hasPrev?: boolean;
  hasNext?: boolean;
  customPaginationText?: React.ReactNode;
  rowClassName?: (item: T) => string | undefined;
  className?: string;
  // Selection
  selectedKeys?: Set<string | number>;
  onSelectionChange?: (keys: Set<string | number>) => void;
  // Empty state customization
  emptyStateIcon?: React.ComponentType<{ className?: string }>;
  emptyStateTitle?: string;
  emptyStateDescription?: string;
  tableClassName?: string;
  topActionSlot?: React.ReactNode;
}

export function CustomTable<T>({
  icon,
  title,
  subtitle,
  data,
  columns,
  keyExtractor,
  searchPlaceholder,
  searchValue = "",
  onSearchChange,
  filters,
  sortKey,
  sortDir = "desc",
  onSort,
  currentPage = 1,
  totalPages = 1,
  onPageChange,
  pageSize = 10,
  onPageSizeChange,
  pageSizeOptions = [10, 20, 50, 100],
  totalItemsCount = 0,
  itemsName = "items",
  onRowClick,
  onPrevPage,
  onNextPage,
  hasPrev = false,
  hasNext = false,
  customPaginationText,
  rowClassName,
  className,
  selectedKeys,
  onSelectionChange,
  emptyStateIcon,
  emptyStateTitle,
  emptyStateDescription,
  tableClassName,
  topActionSlot,
}: CustomTableProps<T>) {
  const startItem = totalItemsCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalItemsCount);

  const [gotoValue, setGotoValue] = React.useState("");
  const commitGoto = () => {
    const n = Number.parseInt(gotoValue, 10);
    if (!Number.isNaN(n) && onPageChange) {
      onPageChange(Math.min(Math.max(1, n), Math.max(1, totalPages)));
    }
    setGotoValue("");
  };

  return (
    <div className={cn("card-surface min-w-0 overflow-hidden flex flex-col", className)}>
      {/* Title Header Block (Optional) */}
      {(title || topActionSlot) && (
        <div className="flex flex-wrap items-center justify-between gap-3.5 px-6 py-4 bg-card">
          <div className="flex min-w-0 items-center gap-3.5">
            {icon && (
              <div className="flex size-9 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary shadow-xs">
                {icon}
              </div>
            )}
            {title && (
              <div className="min-w-0">
                <h2 className="text-base font-bold text-foreground leading-tight">{title}</h2>
                {subtitle && (
                  <p className="mt-0.5 text-xs text-muted-foreground font-semibold">{subtitle}</p>
                )}
              </div>
            )}
          </div>
          {topActionSlot}
        </div>
      )}

      {/* Filter / Search Bar */}
      {(onSearchChange || filters) && (
        <div className="flex flex-wrap items-center gap-2 border-t border-b border-border/80 bg-muted/15 px-6 py-3.5">
          {onSearchChange && (
            <div className="relative w-full max-w-[220px]">
              <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground opacity-75" />
              <input
                type="text"
                placeholder={searchPlaceholder || "Search..."}
                value={searchValue}
                onChange={(e) => onSearchChange(e.target.value)}
                className="h-8 w-full rounded-lg border border-border bg-card pl-8 pr-7 text-xs outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all text-foreground placeholder:text-muted-foreground shadow-xs"
              />
              {searchValue && (
                <button
                  type="button"
                  onClick={() => onSearchChange("")}
                  className="absolute right-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>
          )}
          {filters}
        </div>
      )}

      {/* Table Container or Empty State */}
      {data.length > 0 ? (
        <>
          <div className="overflow-x-auto custom-scrollbar flex-1">
            <table className={cn("w-full text-sm", tableClassName)}>
              <thead className="border-b border-border/80 bg-muted/20 text-muted-foreground">
                <tr className="text-left text-[11px] font-bold uppercase tracking-wider">
                  {selectedKeys && onSelectionChange && (
                    <th className="w-10 px-6 py-3.5 align-middle">
                      <input
                        type="checkbox"
                        checked={data.length > 0 && data.every(item => selectedKeys.has(keyExtractor(item)))}
                        onChange={(e) => {
                          const newSelected = new Set(selectedKeys);
                          if (e.target.checked) {
                            data.forEach(item => newSelected.add(keyExtractor(item)));
                          } else {
                            data.forEach(item => newSelected.delete(keyExtractor(item)));
                          }
                          onSelectionChange(newSelected);
                        }}
                        className="size-4 rounded border-border bg-card accent-primary cursor-pointer block"
                      />
                    </th>
                  )}
                  {columns.map((col, idx) => (
                    <th key={idx} className={cn("px-6 py-3.5 font-bold", col.className)}>
                      {col.sortKey && onSort ? (
                        <button
                          type="button"
                          onClick={() => onSort(col.sortKey!)}
                          className="inline-flex items-center gap-1 uppercase tracking-wider transition-colors hover:text-foreground"
                        >
                          {col.header}
                          {sortKey === col.sortKey ? (
                            sortDir === "asc" ? (
                              <ArrowUp className="size-3 text-primary" />
                            ) : (
                              <ArrowDown className="size-3 text-primary" />
                            )
                          ) : (
                            <ArrowUpDown className="size-3 opacity-40" />
                          )}
                        </button>
                      ) : (
                        col.header
                      )}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {data.map((item, idx) => (
                  <tr
                    key={`${keyExtractor(item)}-${idx}`}
                    onClick={() => onRowClick?.(item)}
                    className={cn(
                      "transition-colors hover:bg-muted/15",
                      onRowClick && "cursor-pointer",
                      rowClassName?.(item)
                    )}
                  >
                    {selectedKeys && onSelectionChange && (
                      <td 
                        className="w-10 px-6 py-3.5 align-middle"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <input
                          type="checkbox"
                          checked={selectedKeys.has(keyExtractor(item))}
                          onChange={(e) => {
                            const newSelected = new Set(selectedKeys);
                            const key = keyExtractor(item);
                            if (e.target.checked) {
                              newSelected.add(key);
                            } else {
                              newSelected.delete(key);
                            }
                            onSelectionChange(newSelected);
                          }}
                          className="size-4 rounded border-border bg-card accent-primary cursor-pointer block"
                        />
                      </td>
                    )}
                    {columns.map((col, colIdx) => (
                      <td key={colIdx} className={cn("px-6 py-3.5 whitespace-nowrap align-middle", col.className)}>
                        {col.cell(item)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          {((totalPages !== undefined && totalPages >= 1) || (onPrevPage && onNextPage)) && (
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 border-t border-border/85 px-6 py-4 bg-muted/5">
              <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground font-medium">
                {customPaginationText ? (
                  <span>{customPaginationText}</span>
                ) : (
                  <span>
                    Showing <span className="font-semibold text-foreground">{startItem}</span> to{" "}
                    <span className="font-semibold text-foreground">{endItem}</span>
                    {totalItemsCount > 0 && (
                      <>
                        {" "}of <span className="font-semibold text-foreground">{totalItemsCount}</span>
                      </>
                    )}
                    {" "}{itemsName}
                  </span>
                )}
                {onPageSizeChange && pageSize && (
                  <div className="flex items-center gap-1.5 border-l border-border/60 pl-4">
                    <span>Show</span>
                    <select
                      value={pageSize}
                      aria-label="Rows per page"
                      onChange={(e) => onPageSizeChange(Number(e.target.value))}
                      className="h-7 rounded-md border border-border bg-card px-2 py-0.5 text-xs font-semibold text-foreground outline-none focus:border-primary/50 transition-all cursor-pointer shadow-xs"
                    >
                      {pageSizeOptions.map((size) => (
                        <option key={size} value={size}>
                          {size}
                        </option>
                      ))}
                    </select>
                    <span>per page</span>
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center justify-center gap-1.5">
                <button
                  type="button"
                  onClick={() => {
                    if (onPrevPage) onPrevPage();
                    else onPageChange?.(currentPage - 1);
                  }}
                  disabled={onPrevPage ? !hasPrev : currentPage === 1}
                  className="inline-flex h-8 items-center gap-1 rounded-lg border border-border bg-card px-2.5 text-xs font-bold text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 disabled:pointer-events-none transition-colors shadow-xs"
                >
                  <ChevronLeft className="size-3.5" /> Prev
                </button>

                {totalPages && totalPages > 1 && (
                  <div className="flex items-center gap-1">
                    {[...new Set([1, currentPage - 1, currentPage, currentPage + 1, totalPages])].filter(page => page >= 1 && page <= totalPages).sort((a, b) => a - b)
                      .map((page, idx, arr) => {
                        const prevPage = arr[idx - 1];
                        const showEllipsis = prevPage && page - prevPage > 1;
                        return (
                          <React.Fragment key={page}>
                            {showEllipsis && (
                              <span className="px-1.5 text-xs text-muted-foreground font-bold">...</span>
                            )}
                            <button
                              type="button"
                              aria-label={`Page ${page}`}
                              aria-current={currentPage === page ? "page" : undefined}
                              onClick={() => onPageChange?.(page)}
                              className={cn(
                                "inline-flex size-8 items-center justify-center rounded-lg text-xs font-bold transition-all shadow-xs",
                                currentPage === page
                                  ? "bg-primary text-primary-foreground shadow-sm"
                                  : "border border-border bg-card text-muted-foreground hover:text-foreground hover:bg-accent"
                              )}
                            >
                              {page}
                            </button>
                          </React.Fragment>
                        );
                      })}
                  </div>
                )}

                {onPageChange && totalPages > 1 && (
                  <div className="ml-1.5 flex items-center gap-1.5 border-l border-border/60 pl-3">
                    <span className="text-xs font-medium text-muted-foreground">Go to</span>
                    <input
                      type="text"
                      inputMode="numeric"
                      value={gotoValue}
                      placeholder={String(currentPage)}
                      onChange={(e) => setGotoValue(e.target.value.replace(/[^0-9]/g, ""))}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") commitGoto();
                      }}
                      onBlur={() => {
                        if (gotoValue) commitGoto();
                      }}
                      className="h-8 w-14 rounded-lg border border-border bg-card text-center text-xs font-semibold text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all shadow-xs"
                      aria-label="Go to page"
                    />
                  </div>
                )}

                <button
                  type="button"
                  onClick={() => {
                    if (onNextPage) onNextPage();
                    else onPageChange?.(currentPage + 1);
                  }}
                  disabled={onNextPage ? !hasNext : currentPage === totalPages}
                  className="inline-flex h-8 items-center gap-1 rounded-lg border border-border bg-card px-2.5 text-xs font-bold text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 disabled:pointer-events-none transition-colors shadow-xs"
                >
                  Next <ChevronRight className="size-3.5" />
                </button>
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="p-6">
          <EmptyState
            icon={emptyStateIcon}
            title={emptyStateTitle || "No records matching the filter criteria"}
            description={emptyStateDescription || "Adjust your search parameters or check back later."}
          />
        </div>
      )}
    </div>
  );
}
