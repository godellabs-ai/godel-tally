import { expect, test, type Page } from "@playwright/test";
import { findingsFixture } from "../fixtures/findings";
import type { DataInventory, SampleDataStatus } from "../../lib/tally";
const counts: DataInventory = { ai_logs: 135, inventory_entities: 820, findings: 129, endpoint_hosts: 129, destination_hosts: 129, endpoint_users: 129, connectors: 43, connector_runs: 43, ingestion_receipts: 43, scanner_runs: 1, audit_events: 1, registry_sanctions: 90 };
const zero = Object.fromEntries(Object.keys(counts).map(key => [key, 0])) as unknown as DataInventory;
async function setup(page: Page, { populated = false, role = "admin", failInventory = false } = {}) {
  await page.context().addCookies([{ name: "tally_session", value: "sample-test", url: test.info().project.use.baseURL! }]);
  let hasFindings = populated;
  let status: SampleDataStatus = { present: false, state: "absent", created_at: null, counts: zero, connector_types: ["nextdns_csv_v1"], categories: ["Internet security"], observation_kinds: ["dns_query"] };
  const writes: { path: string; body: unknown }[] = [];
  await page.route("**/api/v1/auth/**", route => route.fulfill({ json: new URL(route.request().url()).pathname.endsWith("/email") ? { configured: false, enabled: false, source: null, provider: "smtp", from_email: "", from_name: null, settings: {}, secrets_set: [], public_url_configured: true } : { user: { id: "sample-test", role, email: "admin@example.test" } } }));
  await page.route("**/api/v1/tally/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === "POST") {
      writes.push({ path, body: route.request().postDataJSON() });
      if (path.endsWith("/data/sample")) { status = { ...status, present: true, state: "ready", counts }; hasFindings = true; }
      if (path.endsWith("/data/sample/delete")) status = { ...status, present: false, state: "absent", counts: zero };
    }
    if (path.endsWith("/estate")) return route.fulfill({ status: failInventory ? 503 : 200, json: { records: [], next_cursor: null, content_retained: false } });
    if (path.endsWith("/findings")) return route.fulfill({ json: hasFindings ? findingsFixture() : { sanctioned: [], unsanctioned: [], authorization_queue: [] } });
    if (path.endsWith("/data/sample") || path.endsWith("/data/sample/delete")) return route.fulfill({ json: status });
    return route.fulfill({ json: counts });
  });
  return writes;
}
test("empty overview adds evaluation data and refreshes findings", async ({ page }) => {
  const writes = await setup(page); await page.goto("/");
  await expect(page.getByRole("heading", { name: "See your AI estate come to life" })).toBeVisible();
  await page.getByRole("button", { name: "Add evaluation data", exact: true }).click();
  await expect(page.getByRole("button", { name: "Add evaluation data", exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Overview findings" }).getByText("Unapproved AI", { exact: true })).toBeVisible();
  expect(writes.filter(w => w.path.endsWith("/data/sample"))).toHaveLength(1);
});
for (const scenario of [{ populated: true }, { role: "member" }, { failInventory: true }]) {
  test(`overview hides sample action for ${JSON.stringify(scenario)}`, async ({ page }) => {
    await setup(page, scenario); await page.goto("/");
    await expect(page.getByRole("region", { name: "Overview findings" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Add evaluation data", exact: true })).toHaveCount(0);
  });
}
test("settings adds samples alongside existing data and confirms scoped removal", async ({ page }) => {
  const writes = await setup(page, { populated: true }); await page.goto("/settings");
  await page.getByRole("button", { name: "Add evaluation data", exact: true }).click();
  await page.getByRole("button", { name: "Remove evaluation data…", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Your other data is preserved");
  await expect(dialog.getByRole("button", { name: "Delete permanently" })).toBeDisabled();
  await dialog.getByRole("textbox").fill("delete");
  await expect(dialog.getByRole("button", { name: "Delete permanently" })).toBeDisabled();
  await dialog.getByRole("textbox").fill("delete evaluation data");
  await dialog.getByRole("button", { name: "Delete permanently" }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByText("Evaluation data removed. Your other data is preserved.")).toBeVisible();
  expect(writes.at(-1)).toEqual({ path: "/api/v1/tally/data/sample/delete", body: { confirmation: "delete evaluation data" } });
  expect(writes.some(w => w.path.endsWith("/data/delete"))).toBe(false);
});
test("deletion previews the target, invalidates changed filters, and requires confirmation", async ({ page }) => {
  const writes = await setup(page); await page.goto("/settings");
  const area = page.getByRole("region", { name: "Tally data deletion" });
  await expect(area.getByRole("button", { name: "Delete…", exact: true })).toBeDisabled();
  await area.getByRole("checkbox", { name: /Retained AI logs/ }).check();
  await area.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(area.getByRole("heading", { name: "Matches to delete" })).toBeVisible();
  await area.getByRole("checkbox", { name: /AI estate inventory/ }).check();
  await expect(area.getByRole("heading", { name: "Matches to delete" })).toHaveCount(0);
  await area.getByRole("button", { name: "Delete…", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("button", { name: "Delete permanently" })).toBeDisabled();
  await dialog.getByRole("textbox").fill("delete");
  await dialog.getByRole("button", { name: "Delete permanently" }).click();
  await expect(dialog).toHaveCount(0);
  expect(writes.at(-1)).toEqual({ path: "/api/v1/tally/data/delete", body: { scopes: ["ai_logs", "inventory"], before: null, confirmation: "DELETE SELECTED DATA" } });
  await area.getByRole("button", { name: "Delete All…", exact: true }).click();
  await expect(dialog).toContainText("Confirm deletion of all data");
  await dialog.getByRole("textbox").fill("delete");
  await expect(dialog.getByRole("button", { name: "Delete permanently" })).toBeDisabled();
  await dialog.getByRole("textbox").fill("delete all");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  expect(writes.filter(w => w.path.endsWith("/data/delete"))).toHaveLength(1);
});
test("failed sample removal stays in the dialog for retry", async ({ page }) => {
  await setup(page); await page.goto("/settings");
  await page.getByRole("button", { name: "Add evaluation data", exact: true }).click();
  await page.route("**/api/v1/tally/data/sample/delete", route => route.fulfill({ status: 503, json: { title: "Storage temporarily unavailable" } }));
  await page.getByRole("button", { name: "Remove evaluation data…", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("textbox").fill("delete evaluation data");
  await dialog.getByRole("button", { name: "Delete permanently" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Storage temporarily unavailable");
  await expect(dialog.getByRole("button", { name: "Delete permanently" })).toBeEnabled();
});

test("sample connectors are labeled and open a new live configuration", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/tally/connectors", route => route.fulfill({ json: { items: [{ connector_instance_id: "sample-connector", connector_type: "servicenow_agents_api_v1", sample: true, health: "paused", display_name: "ServiceNow", friendly_name: "ServiceNow · Production", transport: "pull", descriptor: {} }], jobs: [] } }));
  await page.route("**/api/v1/tally/scans", route => route.fulfill({ json: { items: [] } }));
  await page.goto("/connectors");
  const card = page.locator(".card-surface").filter({ has: page.getByRole("heading", { name: "ServiceNow AI Agents", exact: true }) });
  await expect(card).toContainText("Evaluation data available");
  await card.getByRole("button", { name: "Connect", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Configure ServiceNow AI Agents", exact: true })).toBeVisible();
  await expect(page.getByRole("dialog")).not.toContainText("ServiceNow · Production");
});
