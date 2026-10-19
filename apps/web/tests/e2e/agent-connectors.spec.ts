import { expect, test } from "@playwright/test";

test("one platform tab includes cloud and managed agents with usable provider setup", async ({ page }) => {
  await page.goto("/connectors");
  await expect(page.getByRole("tab", { name: /AI agents & platforms/ })).toBeVisible();
  await expect(page.getByRole("tab", { name: /Managed AI Agents|Cloud AI platforms/i })).toHaveCount(0);
  for (const title of ["ServiceNow AI Agents", "n8n AI workflows", "Microsoft Copilot Studio", "LangSmith / LangGraph agents", "Dify AI applications", "AWS Bedrock & SageMaker", "Azure OpenAI & Foundry", "Google Vertex AI"]) {
    await expect(page.getByText(title, { exact: true })).toBeVisible();
  }
  for (const brand of ["ServiceNow", "n8n", "Microsoft Copilot Studio", "LangSmith / LangGraph", "Dify"]) {
    const logo = page.getByRole("img", { name: brand, exact: true }).first();
    await expect(logo).toBeVisible();
    await expect.poll(() => logo.evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
  }

  await page.getByText("Microsoft Copilot Studio", { exact: true }).click();
  await expect(page.getByRole("heading", { name: "Configure Microsoft Copilot Studio" })).toBeVisible();
  await expect(page.getByLabel("Dataverse environment URL")).toBeVisible();
  await expect(page.getByRole("textbox", { name: /^OAuth access token/ })).toHaveAttribute("type", "password");
  await expect(page.getByText(/read access to the bot table/)).toBeVisible();
  await expect(page.getByLabel("Platform", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();

  await page.getByText("LangSmith / LangGraph agents", { exact: true }).click();
  await expect(page.getByLabel("Deployment URL")).toBeVisible();
  await expect(page.getByRole("textbox", { name: /^LangSmith API key/ })).toHaveAttribute("type", "password");
  await expect(page.getByText(/search assistants/)).toBeVisible();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
});

test("every connector category displays loaded brand assets", async ({ page }) => {
  await page.goto("/connectors");
  for (const [category, brands] of [
    ["AI agents & platforms", ["ServiceNow", "n8n", "Microsoft Copilot Studio", "LangSmith / LangGraph", "Dify", "Amazon Web Services", "Microsoft Azure", "Google Cloud"]],
    ["AI gateways & proxies", ["Cloudflare", "LiteLLM Proxy"]],
    ["Internet access & security", ["Microsoft", "CrowdStrike", "Rapid7", "Netskope", "Cloudflare", "Cato Networks", "Zscaler", "NextDNS", "Palo Alto Networks"]],
    ["Infrastructure discovery", ["Amazon Web Services", "Microsoft Azure", "Google Cloud", "Kubernetes", "Gödel Tally"]],
  ] as const) {
    await page.getByRole("tab", { name: new RegExp(category) }).click();
    for (const brand of brands) {
      const logo = page.getByRole("img", { name: brand, exact: true }).first();
      await logo.scrollIntoViewIfNeeded();
      await expect.poll(() => logo.evaluate(image => (image as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
    }
  }
});

test("Dify setup submits a scoped scheduled connection without sending an import", async ({ page }) => {
  let submitted: Record<string, unknown> | undefined;
  await page.route("**/api/v1/tally/connectors/schedules", async route => {
    submitted = route.request().postDataJSON();
    await route.fulfill({ json: { connector_instance_id: "00000000-0000-0000-0000-000000000001" } });
  });
  await page.goto("/connectors");
  await page.getByText("Dify AI applications", { exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Each connection inventories this application");
  await page.getByLabel("API origin").fill("https://api.dify.ai");
  await page.getByLabel("App ID", { exact: true }).fill("00000000-0000-0000-0000-000000000002");
  await page.getByRole("textbox", { name: /^Application API key/ }).fill("fixture-app-key");
  await page.getByRole("button", { name: "Add Connector", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(submitted).toMatchObject({
    source_kind: "managed_agents", platform: "dify", base_url: "https://api.dify.ai",
    app_id: "00000000-0000-0000-0000-000000000002", api_key: "fixture-app-key",
    acknowledge_source_access: true,
  });
});
