"use client";

import React from "react";
import { LucideIcon, Inbox } from "lucide-react";
import { cn } from "@/lib/utils";

export interface EmptyStateProps {
  icon?: LucideIcon | React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  variant?: "card" | "page";
}

export function EmptyState({
  title,
  description,
  variant = "card",
}: EmptyStateProps) {
  const Icon = Inbox;

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center text-center animate-fade-in w-full",
        variant === "page"
          ? "card-surface min-h-[calc(100vh-8.5rem)] p-12"
          : "p-12 bg-muted/5 border border-dashed border-border/50 rounded-xl max-w-2xl mx-auto my-6 shadow-2xs"
      )}
    >
      <div className="flex size-16 items-center justify-center rounded-2xl bg-primary/5 text-primary border border-primary/10 mb-5 shadow-xs">
        <Icon className="size-8 animate-pulse-subtle" />
      </div>
      <h3 className="text-base font-semibold text-foreground tracking-tight mb-1">
        {title}
      </h3>
      <p className="max-w-md text-xs leading-relaxed text-muted-foreground">
        {description}
      </p>
    </div>
  );
}
