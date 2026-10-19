import { expect, test, type Page } from "@playwright/test";
import { fixture } from "../fixtures/estate";
import { findingsFixture } from "../fixtures/findings";
import { eventStreamFixture } from "../fixtures/event-stream";

async function setup(page: Page) {
  if (!process.env.TALLY_E2E_STORAGE_STATE) await page.context().addCookies([{ name: "tally_session", value: "estate-test", url: test.info().project.use.baseURL! }]);
  await page.route("**/api/v1/auth/**", route => route.fulfill({ json: { user: { id: "estate-test", role: "admin", email: "estate@example.test" } } }));
  await page.route("**/api/v1/tally/**", route => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path.endsWith("/estate") ? fixture() : path.endsWith("/findings") ? findingsFixture() : path.endsWith("/event-stream") ? eventStreamFixture(new URL(route.request().url()).searchParams) : { items: [] } });
  });
}
const graph = (page: Page) => page.getByRole("region", { name: "Overview event flow", exact: true });
const inventory = (page: Page) => page.getByRole("region", { name: "Overview inventory", exact: true });
const findings = (page: Page) => page.getByRole("region", { name: "Overview findings", exact: true });

test("Tally has one four-column overview with the findings table below", async ({ page }) => {
  await setup(page); await page.goto("/");
  for (const name of ["Users", "AI Authorization", "Agents", "MCP Server / Data Source"]) await expect(graph(page).getByText(name, { exact: true })).toBeVisible();
  await expect(graph(page).getByText("Content Classification", { exact: true })).toHaveCount(0);
  await expect(graph(page).getByText("Decision", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /People view|Data view|Protected/ })).toHaveCount(0);
  await expect(inventory(page)).toHaveCount(0);
  await expect(findings(page).getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await graph(page).locator('.flow-node.agent').filter({ hasText: "IT service assistant" }).click();
  await expect(graph(page).locator(".flow-node.agent.locked")).toContainText("IT service assistant");
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(inventory(page)).toHaveCount(0);
});

test("Tally exposure paths preserve callers, exclude unknown protection, and clear", async ({ page }) => {
  await setup(page); await page.goto("/");
  await page.getByRole("button", { name: "Exposure paths", exact: true }).click();
  await expect(page.getByRole("button", { name: "Unprotected devices" })).toHaveCount(0);
  await expect(graph(page).locator('.flow-node.agent')).toHaveCount(2);
  await expect(graph(page).locator('.flow-node.agent').filter({ hasText: "Claude Code" })).toBeVisible();
  await expect(graph(page).locator('.flow-node.agent').filter({ hasText: "Unapproved AI" })).toBeVisible();
  await expect(graph(page).locator(".flow-node.source").filter({ hasText: "api.openai.com" })).toBeVisible();
  await page.getByRole("button", { name: "Flagged for review", exact: true }).click();
  await expect(page.getByText("No matching activity.", { exact: true })).toBeVisible();
  await expect(inventory(page)).toHaveCount(0);
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(inventory(page)).toHaveCount(0);
  await expect.poll(() => graph(page).locator('[style*="radial-gradient"]').evaluate(element => Math.abs(element.clientWidth - Number(element.querySelector("svg.absolute")?.getAttribute("width"))))).toBeLessThan(2);
});

test("authorization nodes select the matching event filter without scrolling or navigating away", async ({ page }) => {
  await setup(page); await page.goto("/");
  for (const [node, label] of [["Sanctioned", "Sanctioned"], ["Unsanctioned", "Unsanctioned"], ["Review", "Authorization Queue"]]) {
    await graph(page).locator(".flow-node.authorization").filter({ has: page.getByText(node, { exact: true }) }).click();
    await expect(findings(page).getByRole("button", { name: label, exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(findings(page).getByRole("table")).toBeVisible();
    await expect(graph(page).locator(".flow-node.authorization.locked")).toHaveCount(1);
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("button", { name: "All activity", exact: true })).toBeInViewport();
  }
  await findings(page).getByRole("button", { name: "Sanctioned", exact: true }).click();
  await expect(findings(page)).toContainText("of 88 events");
});

test("provider findings populate the graph even when estate inventory is empty", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/tally/estate?**", route => route.fulfill({ json: { ...fixture(), records: [] } }));
  await page.goto("/");
  await expect(graph(page).locator(".flow-node.authorization.sanctioned")).toContainText("1 finding");
  await expect(graph(page).locator(".flow-node.authorization.unsanctioned")).toContainText("1 finding");
  await expect(graph(page).locator(".flow-node.agent")).toHaveCount(3);
  await expect(graph(page).locator(".flow-node.source")).toHaveCount(0);
  await expect(findings(page).getByRole("table")).toBeVisible();
});

test("unsanctioned model findings connect to Ollama in Agents and never bypass it", async ({ page }) => {
  await setup(page);
  const data = findingsFixture();
  const finding = data.unsanctioned[0];
  finding.provider.name = "Ollama";
  finding.provider.category = "local_runtime";
  finding.model = { model_id: "llama", key: "llama3.3", name: "Llama 3.3", family: "Llama", country_code: "US", modalities: ["text"], capabilities: ["chat"], catalog: true,
    sanctioned: false, provider_ids: [finding.provider.provider_id], provider_names: ["Ollama"], finding_count: 1, last_used_at: null };
  finding.users = [{ endpoint_user_id: "alice", kind: "email", value: "alice@example.test", email: "alice@example.test", first_seen: finding.first_used_at, last_seen: finding.last_used_at }];
  await page.route("**/api/v1/tally/findings", route => route.fulfill({ json: { ...data, sanctioned: [], authorization_queue: [] } }));
  await page.route("**/api/v1/tally/estate?**", route => route.fulfill({ json: { ...fixture(), records: [] } }));
  await page.goto("/");
  await expect(graph(page).locator('.flow-node.agent')).toHaveCount(1);
  await expect(graph(page).locator('.flow-node.agent')).toContainText("Ollama");
  await expect(graph(page)).not.toContainText("Llama 3.3");
  await expect(graph(page).locator('.flow-node.source')).toHaveCount(0);
  const link = graph(page).locator('[data-flow-source="Authorization:Unsanctioned"][data-flow-target="Agent:Ollama"]');
  await expect(link).toHaveCount(1);
  await graph(page).locator('.flow-node.authorization.unsanctioned').click();
  await expect(graph(page).locator('.flow-node.agent.active')).toContainText("Ollama");
  await expect(link).toHaveCount(1);
  await expect(graph(page).locator('[data-flow-source^="Authorization:"][data-flow-target^="Source:"]')).toHaveCount(0);
});

test("refresh updates the overview graph and preserves the selected event status", async ({ page }) => {
  await setup(page);
  const data = findingsFixture();
  let eventRequests = 0;
  await page.route("**/api/v1/tally/findings", route => route.fulfill({ json: data }));
  await page.route("**/api/v1/tally/event-stream?**", route => {
    eventRequests++;
    return route.fulfill({ json: eventStreamFixture(new URL(route.request().url()).searchParams) });
  });
  await page.goto("/");
  await expect(graph(page).locator(".flow-node.authorization.unsanctioned")).toBeVisible();
  await findings(page).getByRole("button", { name: "Sanctioned", exact: true }).click();
  await expect(findings(page)).toContainText("of 88 events");
  const beforeRefresh = eventRequests;
  const row = data.unsanctioned.shift()!;
  row.status = "sanctioned"; row.provider.sanctioned = true;
  data.sanctioned.push(row);
  await page.getByRole("button", { name: "Refresh overview" }).click();
  await expect(graph(page).locator(".flow-node.authorization.sanctioned")).toContainText("2 findings");
  await expect(graph(page).locator(".flow-node.authorization.unsanctioned")).toHaveCount(0);
  await expect.poll(() => eventRequests).toBeGreaterThan(beforeRefresh);
  await expect(findings(page).getByRole("button", { name: "Sanctioned", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(findings(page).getByRole("table")).toBeVisible();
});

test("legacy findings links retain the requested status filter on overview", async ({ page }) => {
  await setup(page); await page.goto("/findings?view=sanctioned");
  await expect(page).toHaveURL(/\/\?view=sanctioned#findings$/);
  await expect(findings(page).getByRole("button", { name: "Sanctioned", exact: true })).toHaveAttribute("aria-pressed", "true");
});

test("graph counts distinct findings across users and exposes hidden AI application agents", async ({ page }) => {
  await setup(page);
  const data = findingsFixture();
  const approved = data.sanctioned[0];
  approved.users = ["alice@example.test", "bob@example.test"].map(value => ({ endpoint_user_id: value, kind: "email", value, email: value, first_seen: approved.first_used_at, last_seen: approved.last_used_at }));
  data.sanctioned = Array.from({ length: 30 }, (_, index) => ({ ...approved, finding_id: `finding-${index}`, provider: { ...approved.provider, provider_id: `provider-${index}`, name: `Provider ${index}` } }));
  await page.route("**/api/v1/tally/findings", route => route.fulfill({ json: data }));
  await page.route("**/api/v1/tally/estate?**", route => route.fulfill({ json: { ...fixture(), records: [] } }));
  await page.goto("/");
  await expect(graph(page).locator(".flow-node.authorization.sanctioned")).toContainText("30 findings");
  const agents = graph(page).getByRole("group", { name: "Agents nodes", exact: true });
  await graph(page).getByRole("button", { name: "Show more agents" }).click();
  await expect.poll(() => agents.evaluate(element => element.scrollTop)).toBeGreaterThan(0);
  await graph(page).getByRole("textbox", { name: "Search Agents" }).fill("Provider 29");
  await expect.poll(() => agents.evaluate(element => element.scrollTop)).toBe(0);
  await expect(agents.locator(".flow-node.agent").first()).toContainText("Provider 29");
  await expect(graph(page).locator(".flow-node.source")).toHaveCount(0);
  await graph(page).getByRole("button", { name: "AI Authorization", exact: true }).click();
  await expect(findings(page).getByRole("button", { name: "Authorization Queue", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "All activity", exact: true })).toBeInViewport();
});

test("Tally keeps its graph scrollable on mobile without inventory controls", async ({ page }) => {
  await setup(page); await page.setViewportSize({ width: 390, height: 844 }); await page.goto("/");
  await expect(graph(page)).toBeVisible();
  await expect(inventory(page)).toHaveCount(0);
  await expect(page.getByRole("textbox", { name: "Search inventory" })).toHaveCount(0);
  expect(await graph(page).locator('[data-overview-canvas]').evaluate(element => element.scrollWidth > element.clientWidth)).toBe(true);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true);
});


test("graph pagination and refresh work without the inventory table", async ({ page }) => {
  await setup(page);
  const data = fixture();
  let secondPages = 0;
  await page.route("**/api/v1/tally/estate?**", route => {
    const after = new URL(route.request().url()).searchParams.get("after");
    if (after) secondPages++;
    return route.fulfill({ json: { ...data, records: after ? data.records.slice(8) : data.records.slice(0, 8), next_cursor: after ? null : "page-two" } });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(graph(page).locator(".flow-node.agent").filter({ hasText: "IT service assistant" })).toBeVisible();
  await page.getByRole("button", { name: "Refresh overview" }).click();
  await expect.poll(() => secondPages).toBe(2);
  await expect(graph(page).locator(".flow-node.agent").filter({ hasText: "IT service assistant" })).toBeVisible();
  await expect(inventory(page)).toHaveCount(0);
});
