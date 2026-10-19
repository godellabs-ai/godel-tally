"use client";

import { useEffect, useState } from "react";
import { Moon, Sun } from "lucide-react";

import { useTallyTheme } from "@/components/theme-provider";

export function ThemeToggle() {
  const { theme, setTheme } = useTallyTheme();
  const [mounted, setMounted] = useState(false);

  // Hydration-safe client readiness flag; rendering before mount would expose
  // a server/client theme mismatch.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setMounted(true), []);
  const dark = theme === "dark";

  return (
    <button
      type="button"
      aria-label="Toggle color theme"
      onClick={() => setTheme(dark ? "light" : "dark")}
      className="inline-flex size-8 items-center justify-center rounded-md border border-border bg-card text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
    >
      {mounted && dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </button>
  );
}
