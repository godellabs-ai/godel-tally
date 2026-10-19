"use client";

import React from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

import { cn } from "@/lib/utils";

export function Pagination({
  currentPage,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
  pageSizeOptions = [10, 20, 50, 100],
  itemsName = "items",
}: {
  currentPage: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (size: number) => void;
  pageSizeOptions?: number[];
  itemsName?: string;
}) {
  const startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  const endItem = Math.min(currentPage * pageSize, totalItems);
  const visiblePages = [...new Set([1, currentPage - 1, currentPage, currentPage + 1, totalPages])]
    .filter(page => page >= 1 && page <= totalPages).sort((a, b) => a - b);

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 border-t border-border/85 px-6 py-4 bg-muted/5">
      <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground font-medium">
        <span>
          Showing <span className="font-semibold text-foreground">{startItem}</span> to{" "}
          <span className="font-semibold text-foreground">{endItem}</span>
          {totalItems > 0 && (
            <>
              {" "}of <span className="font-semibold text-foreground">{totalItems}</span>
            </>
          )}
          {" "}{itemsName}
        </span>
        {onPageSizeChange && pageSize && (
          <div className="flex items-center gap-1.5 border-l border-border/60 pl-4">
            <span>Show</span>
            <select
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              aria-label="Rows per page"
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
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="inline-flex h-8 items-center gap-1 rounded-lg border border-border bg-card px-2.5 text-xs font-bold text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 disabled:pointer-events-none transition-colors shadow-xs cursor-pointer"
        >
          <ChevronLeft className="size-3.5" /> Prev
        </button>

        {totalPages > 1 && (
          <div className="flex items-center gap-1">
            {visiblePages
              .map((page, idx, arr) => {
                const prevPage = arr[idx - 1];
                const showEllipsis = prevPage && page - prevPage > 1;
                return (
                  <React.Fragment key={page}>
                    {showEllipsis && (
                      <span className="px-1.5 text-xs text-muted-foreground font-bold">
                        ...
                      </span>
                    )}
                    <button
                      type="button"
                      aria-label={`Page ${page}`}
                      aria-current={currentPage === page ? "page" : undefined}
                      onClick={() => onPageChange(page)}
                      className={cn(
                        "inline-flex size-8 items-center justify-center rounded-lg text-xs font-bold transition-all shadow-xs cursor-pointer",
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

        <button
          type="button"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="inline-flex h-8 items-center gap-1 rounded-lg border border-border bg-card px-2.5 text-xs font-bold text-muted-foreground hover:text-foreground hover:bg-accent disabled:opacity-50 disabled:pointer-events-none transition-colors shadow-xs cursor-pointer"
        >
          Next <ChevronRight className="size-3.5" />
        </button>
        <form key={`${currentPage}-${totalPages}`} className="ml-2 flex items-center gap-1.5 text-xs" onSubmit={event => {
          event.preventDefault();
          const page = Number(new FormData(event.currentTarget).get("page"));
          if (Number.isInteger(page) && page >= 1 && page <= totalPages) onPageChange(page);
        }}>
          <label className="flex items-center gap-1.5">Go to page<input name="page" type="number" min={1} max={totalPages} required defaultValue={currentPage} className="h-8 w-16 rounded-md border border-border bg-card px-2 text-foreground"/></label>
          <span>of {totalPages.toLocaleString()}</span>
          <button type="submit" className="h-8 rounded-md border border-border bg-card px-2 font-semibold">Go</button>
        </form>
      </div>
    </div>
  );
}
