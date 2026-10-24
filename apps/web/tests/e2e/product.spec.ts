import { expect, test } from "@playwright/test";

const productScreens = [
  ["/", "Overview"],
  ["/findings", "Overview"],
  ["/connectors", "Connectors"],
  ["/inventory", "People & devices"],
  ["/registry", "AI Registry"],
  ["/audit", "Audit logs"],
  ["/settings", "Settings"],
] as const;

test("the simplified product screens render from the Tally API", async ({ page }) => {
  for (const [path, heading] of productScreens) {
    await page.goto(path);
    await expect(page.getByRole("main")).toHaveCount(1);
    if (path === "/") {
      await expect(page.getByRole("heading", { name: "Overview", exact: true })).toHaveCount(1);
      await expect(page.getByRole("heading", { name: "AI usage at a glance", exact: true })).toHaveCount(0);
    }
    await expect(page.getByRole("heading", { name: heading, exact: true }).first()).toBeVisible();
    await expect(page.getByText(/dummy data|placeholder data/i)).toHaveCount(0);
  }
});

test("findings exposes event authorization filters and search", async ({ page }) => {
  await page.goto("/findings");
  const findings = page.getByRole("region", { name: "Overview findings", exact: true });
  await expect(findings.getByRole("group", { name: "Authorization status" }).getByRole("button")).toHaveText(["All", "Unsanctioned", "Authorization Queue", "Sanctioned"]);
  await expect(findings.getByRole("textbox", { name: "Search events" })).toBeVisible();
  await findings.getByRole("button", { name: "Filters", exact: true }).click();
  await expect(findings.getByLabel("Connector", { exact: true })).toBeVisible();
  await findings.getByRole("button", { name: "Authorization Queue", exact: true }).click();
  await expect(findings.getByRole("button", { name: "Authorization Queue", exact: true })).toHaveAttribute("aria-pressed", "true");
  await findings.getByRole("button", { name: "Sanctioned", exact: true }).click();
  await expect(findings.getByRole("button", { name: "Sanctioned", exact: true })).toHaveAttribute("aria-pressed", "true");
});

test("registry supports provider and model policy workflows", async ({ page }) => {
  await page.goto("/registry");
  await expect(page.getByRole("tab", { name: /Direct providers/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Managed AI/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /AI gateways/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Enterprise apps/ })).toBeVisible();
  await expect(page.getByRole("button", { name: "All sanction statuses" })).toBeVisible();
  await page.getByRole("tab", { name: /AI Models/ }).click();
  await page.getByRole("button", { name: "All capabilities" }).click();
  await page.getByRole("button", { name: "Image generation", exact: true }).click();
  await expect(page.locator("span").filter({ hasText: /^image generation$/ }).first()).toBeVisible();
  await expect(page.getByRole("checkbox").first()).toBeVisible();
});

test("endpoint and SASE connectors expose their native pull configuration", async ({ page }) => {
  await page.goto("/connectors");
  await page.getByRole("tab", { name: /Internet access & security/ }).click();
  await expect(page.getByText("CrowdStrike Falcon EDR", { exact: true })).toBeVisible();

  await page.getByText("Microsoft Defender EDR", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configure Microsoft Defender EDR" })).toBeVisible();
  await expect(page.getByLabel("Tenant ID")).toBeVisible();
  await expect(page.getByLabel("Client ID")).toBeVisible();
  await expect(page.locator("#connector-field-client_secret")).toBeVisible();
  await expect(page.getByLabel("Network events per poll")).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();

  await page.getByText("Cato Networks", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configure Cato Networks" })).toBeVisible();
  await expect(page.getByLabel("Account ID")).toBeVisible();
  await expect(page.locator("#connector-field-api_key")).toBeVisible();
  await expect(page.getByLabel("API Hostname")).toHaveValue("api.catonetworks.com");
  await expect(page.getByLabel("Events per poll")).toBeVisible();
});

test("connectors and data removal keep the primary actions close", async ({ page }) => {
  await page.goto("/connectors");
  await expect(page.getByRole("heading", { name: "Connectors", exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Sync All Feeds", exact: true })).toBeVisible();
  await expect(page.getByText("Import vendor metadata", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("tab", { name: /AI agents & platforms/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /AI gateways & proxies/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Internet access & security/ })).toBeVisible();
  await expect(page.getByText("AWS Bedrock & SageMaker", { exact: true })).toHaveCount(1);
  await page.getByText("AWS Bedrock & SageMaker", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configured", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "New", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("tab", { name: /Infrastructure discovery/ }).click();
  await expect(page.getByText("AWS VPC Flow Logs", { exact: true })).toBeVisible();
  await expect(page.getByText("Azure VNet Flow Logs", { exact: true })).toBeVisible();
  await expect(page.getByText("Google Cloud VPC Flow Logs", { exact: true })).toBeVisible();
  await expect(page.getByText("Native Scanner", { exact: true })).toBeVisible();
  await expect(page.getByText("1 · Choose scope", { exact: true })).toBeVisible();

  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Remove Tally data" })).toBeVisible();
  await expect(page.getByText("Current counts from the Tally API")).toBeVisible();
  await expect(page.getByText(/privacy contract|deployment contract|data lifecycle|dummy data/i)).toHaveCount(0);
});

test("retired product routes are gone", async ({ page }) => {
  for (const path of ["/discover", "/risk", "/coverage", "/reports", "/scanner"]) {
    const response = await page.goto(path);
    expect(response?.status()).toBe(404);
  }
});
