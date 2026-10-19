"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

type Theme = "light" | "dark";

const ThemeContext = createContext<{
  theme: Theme;
  setTheme: (theme: Theme) => void;
} | null>(null);

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>("light");

  useEffect(() => {
    const stored = window.localStorage.getItem("tally-theme");
    const initial = stored === "light" || stored === "dark"
      ? stored
      : "light";
    applyTheme(initial);
    // Hydrate from browser-owned preference only after the server markup is attached.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setThemeState(initial);
  }, []);

  const setTheme = useCallback((next: Theme) => {
    applyTheme(next);
    window.localStorage.setItem("tally-theme", next);
    setThemeState(next);
  }, []);
  const value = useMemo(() => ({ theme, setTheme }), [setTheme, theme]);

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTallyTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTallyTheme must be used within ThemeProvider");
  return context;
}

function applyTheme(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
  document.documentElement.style.colorScheme = theme;
}
