import { expect, test, type Page } from "@playwright/test";

const user = { id: "fixture-admin", email: "admin@example.test", display_name: "Fixture Admin", first_name: "Fixture", last_name: "Admin", role: "admin", disabled: false, has_password: true };

async function fixture(page: Page, failures: (number | "network")[]) {
  let requests = 0;
  await page.clock.install();
  if (!process.env.TALLY_E2E_STORAGE_STATE) await page.context().addCookies([{ name: "tally_session", value: "recovery-test", url: test.info().project.use.baseURL! }]);
  await page.route("**/api/v1/auth/**", async route => {
    const path = new URL(route.request().url()).pathname.split("/").at(-1);
    if (path === "invitations") return route.fulfill({ json: { invitations: [] } });
    if (path === "users") {
      requests++;
      const failure = failures.shift();
      if (failure === "network") return route.abort("failed");
      if (failure) return route.fulfill({ status: failure, body: "<html>Unavailable</html>" });
      return route.fulfill({ json: { users: [user] } });
    }
    return route.fulfill({ json: { user } });
  });
  await page.goto("/users");
  return { get requests() { return requests; } };
}

test("users automatically recovers from gateway and network failures with working controls", async ({ page }) => {
  const f = await fixture(page, [503, "network"]);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Tally is reconnecting");
  await page.clock.fastForward(5000);
  await expect.poll(() => f.requests).toBe(2);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Tally is reconnecting");
  await page.clock.fastForward(5000);
  await expect(page.getByText("Fixture Admin", { exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByRole("alert")).toHaveCount(0);
  await page.getByRole("button", { name: "Edit name", exact: true }).click();
  await expect(page.getByLabel("First name", { exact: true })).toHaveValue("Fixture");
  // A failed stylesheet/JS load would leave the controls unstyled or inert.
  expect(await page.getByRole("button", { name: "Create invitation", exact: true }).evaluate(element => getComputedStyle(element).backgroundColor)).not.toBe("rgba(0, 0, 0, 0)");
});

test("permission denial stops automatic retries and supports an explicit retry", async ({ page }) => {
  const f = await fixture(page, [403]);
  await expect(page.getByRole("main").getByRole("alert")).toContainText("Administrator access is required.");
  await page.clock.fastForward(20_000);
  expect(f.requests).toBe(1);
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("Fixture Admin", { exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByRole("alert")).toHaveCount(0);
  expect(f.requests).toBe(2);
});
