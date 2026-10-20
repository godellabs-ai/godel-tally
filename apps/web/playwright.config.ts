import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? "github" : "list",
  use: {
    baseURL: process.env.TALLY_WEB_URL ?? "http://127.0.0.1:8080",
    ignoreHTTPSErrors: process.env.TALLY_E2E_IGNORE_HTTPS_ERRORS === "1",
    browserName: "chromium",
    storageState: process.env.TALLY_E2E_STORAGE_STATE,
    channel: process.env.CI ? undefined : "chrome",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
});
