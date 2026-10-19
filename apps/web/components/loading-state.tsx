"use client";

import { cn } from "@/lib/utils";

/** Centered spinner for client pages while their data loads. */
export function LoadingState({
  label = "Loading…",
  className,
}: {
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex min-h-[calc(100vh-12rem)] w-full flex-col items-center justify-center gap-3 select-none text-sm text-muted-foreground",
        className
      )}
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/loading_animation/loading-godel-light.gif"
        alt="Loading..."
        className="size-16 object-contain dark:hidden"
      />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="/loading_animation/loading-godel-dark.gif"
        alt="Loading..."
        className="hidden size-16 object-contain dark:block"
      />
      {label && <span className="font-medium animate-pulse">{label}</span>}
    </div>
  );
}
