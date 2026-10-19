import { expect, test, type Page } from "@playwright/test";
import { eventStreamFixture } from "../fixtures/event-stream";
import { findingsFixture } from "../fixtures/findings";
import { fixture } from "../fixtures/estate";

async function setup(page: Page) {
  if (!process.env.TALLY_E2E_STORAGE_STATE) await page.context().addCookies([{ name: "tally_session", value: "stream-test", url: test.info().project.use.baseURL! }]);
  await page.route("**/api/v1/auth/**", route => route.fulfill({ json: { user: { id: "stream-test", role: "admin", email: "test@example.test" } } }));
  const requests: URLSearchParams[] = [];
  await page.route("**/api/v1/tally/**", route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/event-stream")) requests.push(url.searchParams);
    return route.fulfill({ json: url.pathname.endsWith("/event-stream") ? eventStreamFixture(url.searchParams) : url.pathname.endsWith("/findings") ? findingsFixture() : url.pathname.endsWith("/estate") ? fixture() : { items: [] } });
  });
  return requests;
}
const stream = (page: Page) => page.getByRole("region", { name: "Overview findings" });

test("overview shows repeated events separately, jumps to a page, and opens the exact event", async ({ page }) => {
  const requests = await setup(page); await page.goto("/");
  await expect(stream(page).getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(100);
  await expect(page.getByRole("table").getByText("same-model", { exact: true })).toHaveCount(100);
  await expect(stream(page).getByLabel("Rows per page").locator("option")).toHaveText(["100", "250", "500"]);
  await expect(stream(page).getByLabel("Rows per page")).toHaveValue("100");
  await stream(page).getByRole("textbox", { name: "Go to page" }).fill("3");
  await stream(page).getByRole("textbox", { name: "Go to page" }).press("Enter");
  await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(65);
  expect(requests.at(-1)?.get("page")).toBe("3");
  expect(requests.at(-1)?.get("snapshot")).toBe(requests[0].get("snapshot"));
  await page.getByRole("button", { name: "View event 00000000-0000-0000-0000-000000000001", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("00000000-0000-0000-0000-000000000001");
  await expect(page.getByRole("dialog").locator("pre")).toHaveCount(0);
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await stream(page).getByLabel("Rows per page").selectOption("250");
  await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(250);
  expect(requests.at(-1)?.get("page")).toBe("1");
  expect(requests.at(-1)?.get("page_size")).toBe("250");
  await stream(page).getByLabel("Rows per page").selectOption("500");
  await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(265);
  expect(requests.at(-1)?.get("page_size")).toBe("500");
});

test("filters and order query the server and reset pagination", async ({ page }) => {
  const requests = await setup(page); await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await stream(page).getByRole("button", { name: "Page 3", exact: true }).click();
  await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(65);
  await stream(page).getByRole("button", { name: "Filters", exact: true }).click();
  await page.getByRole("textbox", { name: "Search events" }).fill("laptop-even");
  await stream(page).getByLabel("Event type", { exact: true }).selectOption("http_metadata");
  await stream(page).getByLabel("Connector", { exact: true }).selectOption("source-one");
  await stream(page).getByLabel("Source outcome", { exact: true }).fill("allowed");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(stream(page)).toContainText("of 133 events");
  expect(Object.fromEntries(requests.at(-1)!)).toMatchObject({ page: "1", q: "laptop-even", kind: "http_metadata", connector_id: "source-one", outcome: "allowed" });
  await stream(page).getByLabel("Order", { exact: true }).selectOption("oldest");
  await expect(page.getByRole("table").locator("tbody tr").first().getByRole("button", { name: "View event 00000000-0000-0000-0000-000000000001", exact: true })).toBeVisible();
  await stream(page).getByLabel("Time range").selectOption("custom");
  await stream(page).getByLabel("From (local time)").fill("2026-10-15T10:00");
  await stream(page).getByLabel("To (local time)").fill("2026-10-16T10:00");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect.poll(() => requests.at(-1)?.has("from") && requests.at(-1)?.has("until")).toBe(true);
  await page.getByRole("button", { name: "Reset filters" }).click();
  await expect(stream(page)).toContainText("of 265 events");
  await stream(page).getByLabel("Event type", { exact: true }).selectOption("dns_query");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(stream(page).getByText(/No events match/)).toBeVisible();
});

test("failed page loads preserve filters, retry, and keep mobile within the viewport", async ({ page }) => {
  await setup(page); await page.setViewportSize({ width: 390, height: 844 });
  let fail = true;
  await page.route("**/api/v1/tally/event-stream?**", route => fail ? route.fulfill({ status: 503, json: {} }) : route.fulfill({ json: eventStreamFixture(new URL(route.request().url()).searchParams) }));
  await page.goto("/");
  await expect(stream(page).getByRole("alert")).toContainText("Events are unavailable");
  fail = false; await stream(page).getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("table")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true);
  await stream(page).getByRole("button", { name: "Authorization Queue", exact: true }).click();
  await expect(stream(page)).toContainText("of 88 events");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2)).toBe(true);
  await expect(page.getByRole("table")).toBeVisible();
});


test("authorization filters stay in the event table and apply before pagination", async ({ page }) => {
  const requests = await setup(page); await page.goto("/");
  const filters = stream(page).getByRole("group", { name: "Authorization status" });
  await expect(filters.getByRole("button")).toHaveText(["All", "Unsanctioned", "Authorization Queue", "Sanctioned"]);
  await expect(stream(page).getByRole("button", { name: /Registry decisions|^Events$/ })).toHaveCount(0);
  await expect(page.getByRole("table")).toBeVisible();
  await stream(page).getByRole("button", { name: "Page 3", exact: true }).click();
  await expect(stream(page)).toContainText("Showing 201 to 265 of 265 events");
  for (const [label, value, total] of [["Unsanctioned", "unsanctioned", 89], ["Authorization Queue", "authorization_queue", 88], ["Sanctioned", "sanctioned", 88]] as const) {
    await filters.getByRole("button", { name: label, exact: true }).click();
    await expect(filters.getByRole("button", { name: label, exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(stream(page)).toContainText(`of ${total} events`);
    await expect(page.getByRole("table").locator("tbody tr")).toHaveCount(total);
    expect(Object.fromEntries(requests.at(-1)!)).toMatchObject({ status: value, page: "1" });
  }
  await stream(page).getByRole("textbox", { name: "Search events" }).fill("laptop-even");
  await stream(page).getByRole("button", { name: "Apply filters" }).click();
  await expect(stream(page)).toContainText("of 44 events");
  await filters.getByRole("button", { name: "Unsanctioned", exact: true }).click();
  await expect.poll(() => requests.at(-1)?.get("status")).toBe("unsanctioned");
  expect(requests.at(-1)?.get("q")).toBe("laptop-even");
  await stream(page).getByRole("button", { name: "Reset filters" }).click();
  await expect(filters.getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(stream(page)).toContainText("of 265 events");
});


test("investigation columns, row selection, structured evidence, copy, and pivots", async ({ page }) => {
  const requests = await setup(page);
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/");
  await expect(page.getByRole("table").getByRole("columnheader")).toHaveText(["Date", "Authorization", "Person", "Endpoint", "AI provider / Model", "Destination", "Connector", "Details"]);
  await stream(page).getByRole("button", { name: "Unsanctioned", exact: true }).click();
  const first = page.getByRole("table").locator("tbody tr").first();
  await expect(first).toContainText("Unsanctioned");
  await expect(first).toContainText("alice@example.test");
  await expect(first).toContainText("10.20.1.");
  await expect(first).toContainText("Example AI");
  await first.click();
  const panel = page.getByRole("dialog");
  await expect(panel).toContainText("AI request");
  await expect(panel).toContainText("Example AI is marked unsanctioned in AI Registry.");
  for (const section of ["Person & endpoint", "AI service & destination", "Activity & evidence", "Source references", "Follow-up"]) await expect(panel.locator("summary").filter({ hasText: section })).toBeVisible();
  await expect(panel.locator("pre")).toHaveCount(0);
  await expect(panel).toContainText("Allowed");
  await panel.getByRole("button", { name: "Copy investigation details", exact: true }).click();
  await expect(panel.getByRole("status")).toContainText("Investigation details copied");
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toContain("Authorization: Unsanctioned");
  expect(copied).toContain("Source IP: 10.20.1.");
  expect(copied).toContain("AI provider: Example AI");
  expect(copied).toContain("Enforcement is performed in the external system.");
  await panel.getByRole("button", { name: "Person activity", exact: true }).click();
  await expect(panel).toHaveCount(0);
  await expect.poll(() => requests.at(-1)?.get("q")).toBe("alice@example.test");
  expect(requests.at(-1)?.get("status")).toBe("all");
});

test("unattributed discovery shows evidence limits and no invented person or provider", async ({ page }) => {
  await setup(page);
  const response = eventStreamFixture();
  const event = response.items[0];
  event.actor = { hostname: "inference-node-01", source_ip: "10.12.0.5" };
  event.kind = "kubernetes_resource"; event.service = {};
  event.workload = { workload_name: "inference", namespace_name: "ai-tools", workload_kind: "deployment", runtime_image: "ollama/ollama:0.6" };
  response.items = [event]; response.findings = []; response.total = 1; response.total_pages = 1;
  await page.route("**/api/v1/tally/event-stream?**", route => route.fulfill({ json: response }));
  await page.goto("/");
  const first = page.getByRole("table").locator("tbody tr").first();
  await expect(first).toContainText("Not identified");
  await expect(first).toContainText("Provider not identified");
  await first.getByRole("button").focus(); await page.keyboard.press("Enter");
  const panel = page.getByRole("dialog");
  await expect(panel).toContainText("Workload discovered");
  await expect(panel).toContainText("This source did not identify a person.");
  await expect(panel).toContainText("does not by itself establish that a person made an AI request");
  await expect(panel).toContainText("ai-tools");
  await expect(panel).toContainText("ollama/ollama:0.6");
});
