import { ArrowUpRight, CircleAlert } from "lucide-react";
import Link from "next/link";

import { cn } from "@/lib/utils";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <section className="flex flex-wrap items-end justify-between gap-4">
      <div>
        {eyebrow ? <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-primary">{eyebrow}</p> : null}
        <h1 className="mt-1 text-2xl font-bold tracking-tight md:text-3xl">{title}</h1>
        <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted-foreground">{description}</p>
      </div>
      {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
    </section>
  );
}

export function PreviewBanner({ children }: { children?: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 rounded-xl border border-amber-300/60 bg-amber-50/80 px-4 py-3 text-sm text-amber-950 dark:border-amber-900 dark:bg-amber-950/35 dark:text-amber-100">
      <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400" />
      <p>
        <span className="font-bold">No substitute data.</span>{" "}
        {children ?? "Tally shows only authoritative state from the running deployment."}
      </p>
    </div>
  );
}

export function StatusPill({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: "good" | "warn" | "bad" | "neutral" | "purple";
}) {
  const tones = {
    good: "border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/60 dark:text-emerald-300",
    warn: "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/60 dark:text-amber-300",
    bad: "border-red-300 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-300",
    neutral: "border-border bg-muted/60 text-muted-foreground",
    purple: "border-primary/20 bg-primary/10 text-primary",
  };
  return <span className={cn("inline-flex whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-bold", tones[tone])}>{children}</span>;
}

export function Panel({
  title,
  description,
  action,
  children,
  className,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("card-surface overflow-hidden", className)}>
      <div className="flex items-center justify-between gap-4 border-b border-border/80 bg-muted/15 px-6 py-4">
        <div>
          <h2 className="text-sm font-bold">{title}</h2>
          {description ? <p className="mt-0.5 text-xs text-muted-foreground">{description}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function TextLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="inline-flex items-center gap-1 text-xs font-bold text-primary hover:underline">
      {children} <ArrowUpRight className="size-3" />
    </Link>
  );
}

export function MiniBars({ values, tone = "primary" }: { values: number[]; tone?: "primary" | "good" | "warn" }) {
  const color = tone === "good" ? "bg-emerald-500" : tone === "warn" ? "bg-amber-500" : "bg-primary";
  const max = Math.max(1, ...values);
  return (
    <div className="flex h-12 items-end gap-1" role="img" aria-label={`Trend values: ${values.join(", ")}`}>
      {values.map((value, index) => (
        <span key={`${value}-${index}`} className={cn("min-w-1 flex-1 rounded-t opacity-80", color)} style={{ height: `${Math.max(8, (value / max) * 100)}%` }} />
      ))}
    </div>
  );
}
