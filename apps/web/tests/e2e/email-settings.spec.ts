import { expect, test } from "@playwright/test";

test("administrators save email providers without exposing credentials and send a test", async ({ page }) => {
  if (!process.env.TALLY_E2E_STORAGE_STATE) await page.context().addCookies([{ name: "tally_session", value: "email-test", url: test.info().project.use.baseURL! }]);
  const saved: Record<string, unknown>[] = [];
  let tested = "";
  let view = { configured: false, enabled: false, source: null as string | null, provider: "smtp", from_email: "", from_name: null, settings: {}, secrets_set: [] as string[], public_url_configured: true };
  await page.route("**/api/v1/auth/email", async route => {
    if (route.request().method() === "POST") {
      const input = route.request().postDataJSON(); saved.push(input);
      view = { ...view, ...input, source: "database", configured: input.enabled, secrets_set: ["api_key"] };
      delete (view as Record<string, unknown>).secrets;
    }
    return route.fulfill({ json: view });
  });
  await page.route("**/api/v1/auth/email/test", route => {
    tested = route.request().postDataJSON().to;
    return route.fulfill({ json: { sent: true, message: `Test email sent to ${tested}.` } });
  });
  await page.goto("/settings");
  await page.getByLabel("Email provider").selectOption("ses");
  await expect(page.getByLabel("AWS region")).toBeVisible();
  await expect(page.getByLabel("Secret access key")).toHaveAttribute("type", "password");
  await page.getByLabel("Email provider").selectOption("resend");
  await page.getByLabel("From email").fill("tally@example.test");
  await page.getByLabel("API key", { exact: true }).fill("re_fixture");
  await page.getByRole("button", { name: "Save email settings" }).click();
  await expect(page.getByRole("status")).toHaveText("Email settings saved.");
  expect(saved[0]).toMatchObject({ provider: "resend", secrets: { api_key: "re_fixture" } });
  await expect(page.getByLabel("API key", { exact: true })).toHaveValue("");
  await page.getByLabel("Send a test email to").fill("operator@example.test");
  await page.getByRole("button", { name: "Send test", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Test email sent to operator@example.test.");
  expect(tested).toBe("operator@example.test");
  await page.getByLabel("Send email from Tally").uncheck();
  await page.getByRole("button", { name: "Save email settings" }).click();
  await expect(page.getByRole("status")).toHaveText("Email settings saved. Email is turned off.");
  expect(saved[1]).toMatchObject({ enabled: false, secrets: {} });
});
