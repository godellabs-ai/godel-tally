"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

function Switch({
  checked = false,
  className,
  disabled,
  onCheckedChange,
  ...props
}: Omit<React.ComponentProps<"button">, "onChange"> & {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      data-slot="switch"
      data-state={checked ? "checked" : "unchecked"}
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange?.(!checked)}
      className={cn(
        "peer inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent transition-colors outline-none focus-visible:ring-2 focus-visible:ring-primary/30 disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "bg-primary" : "bg-muted",
        className
      )}
      {...props}
    >
      <span
        data-slot="switch-thumb"
        data-state={checked ? "checked" : "unchecked"}
        className={cn(
          "pointer-events-none block size-5 rounded-full bg-white shadow-lg ring-0 transition-transform",
          checked ? "translate-x-5" : "translate-x-0"
        )}
      />
    </button>
  );
}

export { Switch };
