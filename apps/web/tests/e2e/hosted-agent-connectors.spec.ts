import { expect, test } from "@playwright/test";

for (const provider of [
  { platform: "openai", title: "OpenAI Agents", key: "OpenAI API key", scope: "Project ID", value: "proj_test", origin: "https://api.openai.com", brand: "OpenAI" },
  { platform: "claude", title: "Claude Managed Agents", key: "Claude API key", scope: "Workspace ID", value: "wrkspc_test", origin: "https://api.anthropic.com", brand: "Anthropic" },
  { platform: "gemini", title: "Gemini AI Studio Managed Agents", key: "Gemini API key", scope: "Parent resource", value: "projects/test/locations/global", origin: "https://generativelanguage.googleapis.com", brand: "Google Cloud" },
]) {
  test(`${provider.title} creates a scoped scheduled connection`, async ({ page }) => {
    await page.context().addCookies([{ name: "tally_session", value: "fixture", url: test.info().project.use.baseURL! }]);
    await page.route("**/api/v1/auth/**", route => route.fulfill({ json: { user: { id: "fixture", role: "admin", email: "admin@example.test" } } }));
    let submitted: Record<string, unknown> | undefined;
    await page.route("**/api/v1/tally/**", async route => {
      const path = new URL(route.request().url()).pathname;
      if (route.request().method() === "POST") {
        expect(path).toBe("/api/v1/tally/connectors/schedules");
        submitted = route.request().postDataJSON();
        return route.fulfill({ json: { connector_instance_id: "00000000-0000-0000-0000-000000000001" } });
      }
      return route.fulfill({ json: { items: [], jobs: [], records: [], next_cursor: null } });
    });
    await page.goto("/connectors");
    await page.getByRole("tab", { name: /AI agents & platforms/ }).click();
    await page.getByText(provider.title, { exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("heading", { name: `Configure ${provider.title}` })).toBeVisible();
    await expect(dialog.getByLabel("Platform", { exact: true })).toHaveCount(0);
    await expect(dialog.getByLabel("API origin", { exact: true })).toHaveCount(0);
    await dialog.locator("#connector-friendly-name").fill(`${provider.platform} production`);
    await dialog.getByRole("textbox", { name: new RegExp(`^${provider.scope}`) }).fill(provider.value);
    const key = dialog.getByRole("textbox", { name: new RegExp(`^${provider.key}`) });
    await expect(key).toHaveAttribute("type", "password");
    await key.fill("fixture-provider-key");
    await dialog.getByRole("button", { name: "Add Connector", exact: true }).click();
    await expect(dialog).toHaveCount(0);
    expect(submitted).toMatchObject({ source_kind: "managed_agents", platform: provider.platform, base_url: provider.origin, scope_id: provider.value, api_key: "fixture-provider-key", friendly_name: `${provider.platform} production`, acknowledge_source_access: true });
  });
}
