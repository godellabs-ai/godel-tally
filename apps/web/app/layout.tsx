import type { Metadata } from "next";
import { Suspense } from "react";
import { GeistSans } from "geist/font/sans";
import { GeistMono } from "geist/font/mono";

import { Sidebar } from "@/components/sidebar";
import { ThemeProvider } from "@/components/theme-provider";
import { Topbar } from "@/components/topbar";
import { WorkspaceContent } from "@/components/workspace-content";

import "./globals.css";

export const metadata: Metadata = {
  title: "Gödel Tally — AI governance",
  description: "Find and govern the AI providers and models used across your organization.",
  icons: {
    icon: [
      { url: "/favicon-light.svg", media: "(prefers-color-scheme: light)" },
      { url: "/favicon-dark.svg", media: "(prefers-color-scheme: dark)" },
    ],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={`${GeistSans.variable} ${GeistMono.variable} font-sans antialiased`}>
        <ThemeProvider>
          <div className="flex h-dvh overflow-hidden">
            <Suspense fallback={<div className="hidden h-dvh w-52 shrink-0 border-r border-border/40 bg-card md:block" />}><Sidebar /></Suspense>
            <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
              <Suspense fallback={<div className="h-16 border-b border-border/30 bg-card" />}><Topbar /></Suspense>
              <WorkspaceContent>{children}</WorkspaceContent>
            </div>
          </div>
        </ThemeProvider>
      </body>
    </html>
  );
}
