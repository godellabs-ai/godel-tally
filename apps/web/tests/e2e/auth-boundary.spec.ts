import { expect, test } from "@playwright/test";

test("a real failed login revokes the browser session and blocks overview data", async ({ page, baseURL }) => {
  test.skip(!process.env.TALLY_E2E_PASSWORD, "Requires an isolated API and test account");
  await page.context().clearCookies();
  await page.goto("/signin");
  await page.getByLabel("Email", { exact: true }).fill(process.env.TALLY_E2E_EMAIL!);
  await page.getByLabel("Password", { exact: true }).fill(process.env.TALLY_E2E_PASSWORD!);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(`${baseURL}/`);
  // Use browser fetch: its loopback Secure-cookie handling matches the app, while
  // Playwright's separate APIRequestContext treats HTTP cookies differently.
  expect(await page.evaluate(async () => (await fetch("/api/v1/tally/overview")).status)).toBe(200);
  const failed = await page.evaluate(async email => (await fetch("/api/v1/auth/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "incorrect-password" }),
  })).status, process.env.TALLY_E2E_EMAIL!);
  expect(failed).toBe(401);
  expect(await page.evaluate(async () => (await fetch("/api/v1/tally/overview")).status)).toBe(401);
  expect(await page.evaluate(async () => (await fetch("/api/v1/auth/me")).status)).toBe(401);
  for (const path of ["/", "/overview", "/settings", "/users"]) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/signin$/);
    await expect(page.getByRole("heading", { name: "Sign in to Tally" })).toBeVisible();
    await expect(page.getByRole("navigation", { name: "Primary navigation" })).toHaveCount(0);
  }
});
