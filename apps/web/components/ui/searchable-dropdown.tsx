"use client";

import React, { useState, useRef, useEffect, useMemo } from "react";
import { ChevronDown, Search, X, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { DropdownPopover } from "@/components/ui/dropdown-popover";

export interface DropdownOption {
  value: string;
  label: string;
  disabled?: boolean;
}

interface SearchableDropdownProps {
  options: DropdownOption[];
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  searchPlaceholder?: string;
  className?: string;
  triggerClassName?: string;
  disabled?: boolean;
  showSearch?: boolean;
}

export function SearchableDropdown({
  options,
  value,
  onChange,
  placeholder = "Select option...",
  searchPlaceholder = "Search...",
  className,
  triggerClassName,
  disabled = false,
  showSearch = true,
}: SearchableDropdownProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [search, setSearch] = useState("");
  const containerRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        containerRef.current?.scrollIntoView({ block: "nearest", inline: "nearest", behavior: "smooth" });
        if (showSearch) searchInputRef.current?.focus();
      }, 50);
    }
  }, [isOpen, showSearch]);

  const filteredOptions = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return options;
    return options.filter((opt) => opt.label.toLowerCase().includes(q));
  }, [options, search]);

  const selectedOption = useMemo(() => {
    return options.find((opt) => opt.value === value) || null;
  }, [options, value]);

  const handleSelect = (val: string) => {
    onChange(val);
    setIsOpen(false);
  };

  return (
    <div
      ref={containerRef}
      className={cn("relative inline-block w-full text-left", className)}
    >
      <button
        type="button"
        disabled={disabled}
        onClick={() => {
          const nextOpen = !isOpen;
          if (nextOpen) setSearch("");
          setIsOpen(nextOpen);
        }}
        className={cn(
          "flex h-9 w-full items-center justify-between rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground shadow-xs outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/30 transition-all cursor-pointer disabled:pointer-events-none disabled:opacity-50",
          triggerClassName
        )}
      >
        <span className={cn("truncate font-semibold", !selectedOption && "text-muted-foreground/60 font-medium")}>
          {selectedOption ? selectedOption.label : placeholder}
        </span>
        <ChevronDown className={cn("size-4 text-muted-foreground opacity-80 transition-transform duration-200 shrink-0", isOpen && "rotate-180")} />
      </button>

      {isOpen && (
        <DropdownPopover triggerRef={containerRef} onClose={() => setIsOpen(false)}>
          {showSearch && (
            <div className="relative border-b border-border/60 pb-1.5 pt-1 px-1.5">
              <Search className="absolute left-3 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground/60" />
              <input
                ref={searchInputRef}
                type="text"
                placeholder={searchPlaceholder}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="h-8 w-full rounded-md border-0 bg-muted/20 pl-8 pr-7 text-xs text-foreground placeholder:text-muted-foreground/60 outline-none focus:bg-muted/30 focus:ring-0 focus:ring-offset-0 transition-all"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => setSearch("")}
                  className="absolute right-3.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
                >
                  <X className="size-3" />
                </button>
              )}
            </div>
          )}

          <div className="max-h-48 overflow-y-auto custom-scrollbar py-1">
            {filteredOptions.length === 0 ? (
              <div className="px-3 py-4 text-center text-xs font-medium text-muted-foreground">
                No matches found
              </div>
            ) : (
              filteredOptions.map((opt) => {
                const isSelected = opt.value === value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    disabled={opt.disabled}
                    onClick={() => handleSelect(opt.value)}
                    className={cn(
                      "flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-xs text-foreground transition-all",
                      isSelected
                        ? "bg-primary/10 font-bold text-primary hover:bg-primary/15"
                        : "hover:bg-muted/70",
                      opt.disabled && "cursor-not-allowed opacity-40 hover:bg-transparent"
                    )}
                  >
                    <span className="truncate">{opt.label}</span>
                    {isSelected && <Check className="size-3 shrink-0 text-primary" />}
                  </button>
                );
              })
            )}
          </div>
        </DropdownPopover>
      )}
    </div>
  );
}
