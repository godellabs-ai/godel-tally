import { defineConfig } from "@playwright/test";
import base from "./playwright.config";

export default defineConfig(base, {
  testMatch: ["qa-regressions.spec.ts", "auth-pages.spec.ts", "users-recovery.spec.ts", "overview.spec.ts"],
  workers: 2,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report/qa" }]],
  use: { baseURL: "http://127.0.0.1:18081", storageState: { cookies: [], origins: [] } },
  webServer: { command: "node scripts/serve-qa.mjs", url: "http://127.0.0.1:18081/signin", reuseExistingServer: false },
});
