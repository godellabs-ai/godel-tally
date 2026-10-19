"use client";

import { usePathname } from "next/navigation";

export function WorkspaceContent({ children }: { children: React.ReactNode }) {
  const inventory = usePathname() === "/";
  return <main className={`custom-scrollbar min-h-0 flex-1 overflow-y-auto ${inventory ? "p-3" : "px-6 py-7"}`}>
    <div className={inventory ? "w-full" : "mx-auto w-full max-w-[1320px]"}>{children}</div>
  </main>;
}
