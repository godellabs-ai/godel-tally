import { expect, test, type Page } from "@playwright/test";

async function mockAuth(page: Page, { signedIn = false, emailConfigured = true } = {}) {
  const resets: string[] = [];
  const logins: unknown[] = [];
  await page.route("**/api/v1/auth/**", async route => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/auth/", "");
    if (path === "status") return route.fulfill({ json: { first_user_registration_open: false, email_configured: emailConfigured } });
    if (path === "me") return signedIn
      ? route.fulfill({ json: { user: { id: "u", email: "ada@example.test", display_name: "Ada Admin", role: "admin" } } })
      : route.fulfill({ status: 401, json: { error: "Sign in required" } });
    if (path === "logout") { signedIn = false; return route.fulfill({ status: 204 }); }
    if (path === "login") { logins.push(route.request().postDataJSON()); signedIn = false; return route.fulfill({ status: 401, json: { error: "Invalid credentials" } }); }
    if (path === "password-reset/request") {
      resets.push(route.request().postDataJSON().email);
      return emailConfigured ? route.fulfill({ json: { requested: true } })
        : route.fulfill({ status: 503, json: { error: "Email is not set up for this Tally installation, so Tally cannot send reset links." } });
    }
    return route.fulfill({ status: 404, json: { error: `Unexpected test request: ${path}` } });
  });
  return { resets, logins };
}

test("the sign-in page shows an existing session instead of a form that could leave it active", async ({ page }) => {
  await mockAuth(page, { signedIn: true });
  await page.goto("/signin");
  await expect(page.getByRole("heading", { name: "You’re signed in" })).toBeVisible();
  await expect(page.getByText("Signed in as Ada Admin (ada@example.test).")).toBeVisible();
  await expect(page.getByLabel("Password")).toHaveCount(0);
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in to Tally" })).toBeVisible();
  await expect(page.getByRole("button", { name: /SSO/ })).toHaveCount(0);
});

test("a failed sign-in reports the error and stays signed out", async ({ page }) => {
  const { logins } = await mockAuth(page);
  await page.goto("/signin");
  await page.getByLabel("Email").fill("ada@example.test");
  await page.getByLabel("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Invalid credentials")).toBeVisible();
  await expect(page).toHaveURL(/\/signin$/);
  expect(logins).toHaveLength(1);
});

test("successful registration with a failed session check offers sign-in without blaming the browser", async ({ page }) => {
  let registered = false;
  await page.route("**/api/v1/auth/**", async route => {
    const path = new URL(route.request().url()).pathname.split("/").at(-1);
    if (path === "status") return route.fulfill({ json: { first_user_registration_open: !registered, email_configured: false } });
    if (path === "register") { registered = true; return route.fulfill({ json: { user: { email: "ada@example.test" } } }); }
    return route.fulfill({ status: 401, json: { error: "Sign in required" } });
  });
  await page.goto("/signin");
  await page.getByLabel("First name", { exact: true }).fill("Ada");
  await page.getByLabel("Last name", { exact: true }).fill("Admin");
  await page.getByLabel("Email", { exact: true }).fill("ada@example.test");
  await page.getByLabel("Password", { exact: true }).fill("fixture-password-123");
  await page.getByRole("button", { name: "Create account", exact: true }).click();
  await expect(page.locator("form").getByRole("alert")).toHaveText("Your account was created, but Tally could not confirm your session. Try signing in.");
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
  await expect(page.getByLabel("First name", { exact: true })).toHaveCount(0);
});

test("forgot password sends a link without revealing whether the account exists", async ({ page }) => {
  const { resets } = await mockAuth(page);
  await page.goto("/signin");
  await page.getByRole("link", { name: "Forgot password?" }).click();
  await expect(page.getByRole("heading", { name: "Reset your password" })).toBeVisible();
  await page.getByLabel("Email").fill("someone@example.test");
  await page.getByRole("button", { name: "Email me a reset link" }).click();
  await expect(page.getByText("If a Tally account uses someone@example.test, a reset link is on its way.")).toBeVisible();
  expect(resets).toEqual(["someone@example.test"]);
});

test("without email, forgot password explains administrator links and the database reset", async ({ page }) => {
  const { resets } = await mockAuth(page, { emailConfigured: false });
  await page.goto("/forgot-password");
  await expect(page.getByText("Email isn’t set up for this Tally installation")).toBeVisible();
  await expect(page.getByText("Resetting the database is a last resort: it deletes all Tally data and accounts")).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveCount(0);
  expect(resets).toEqual([]);
});
