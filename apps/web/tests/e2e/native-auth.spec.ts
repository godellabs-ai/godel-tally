import { randomUUID } from "node:crypto";
import { connect } from "node:http2";
import { expect, test } from "@playwright/test";

// Opt in only against a fresh, disposable native HTTPS installation.
test.use({ ignoreHTTPSErrors: true });

test("native HTTPS registration, login, and revocation work with multiple cookies", async ({ page, context, baseURL }) => {
  test.skip(process.env.TALLY_E2E_NATIVE_AUTH !== "1", "Requires a disposable native HTTPS installation");
  expect(baseURL).toMatch(/^https:/);
  const email = `native-${randomUUID()}@example.test`;
  const password = `fixture-${randomUUID()}`;
  await context.clearCookies();
  await context.addCookies([{ name: "unrelated_localhost_cookie", value: "fixture", url: baseURL!, secure: true }]);
  const protocols: string[] = [];
  const network = await context.newCDPSession(page);
  await network.send("Network.enable");
  network.on("Network.responseReceived", ({ response }) => {
    if (response.url.endsWith("/api/v1/auth/me") && response.protocol) protocols.push(response.protocol);
  });
  await page.goto("/signin");
  const status = await page.evaluate(async () => (await fetch("/api/v1/auth/status")).json());
  expect(status.first_user_registration_open, "Use an empty disposable database").toBe(true);
  await page.getByLabel("First name", { exact: true }).fill("Native");
  await page.getByLabel("Last name", { exact: true }).fill("Fixture");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Create account", exact: true }).click();
  await expect(page).toHaveURL(`${baseURL}/`);
  expect(await page.evaluate(async () => (await fetch("/api/v1/auth/me")).status)).toBe(200);
  expect(protocols).toContain("h2");
  const registered = (await context.cookies()).find(cookie => cookie.name === "tally_session")!;
  expect(registered).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax" });

  // Exercise explicit HTTP/2 splitting independently of Chromium's encoding choice.
  async function splitSessionStatus(token: string) {
    const client = connect(baseURL!, { rejectUnauthorized: false });
    try {
      return await new Promise<number>((resolve, reject) => {
        client.on("error", reject);
        const request = client.request({
          ":path": "/api/v1/auth/me",
          cookie: ["unrelated_localhost_cookie=fixture", `tally_session=${token}`],
        });
        request.on("response", headers => resolve(Number(headers[":status"])));
        request.on("error", reject);
        request.resume();
        request.end();
      });
    } finally { client.close(); }
  }
  expect(await splitSessionStatus(registered.value)).toBe(200);
  expect(await page.evaluate(async () => (await fetch("/api/v1/auth/logout", { method: "POST" })).status)).toBe(204);
  expect(await splitSessionStatus(registered.value)).toBe(401);
  await page.goto("/signin");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(`${baseURL}/`);
  expect(await page.evaluate(async () => (await fetch("/api/v1/tally/overview")).status)).toBe(200);
  const loggedIn = (await context.cookies()).find(cookie => cookie.name === "tally_session")!;
  expect(await splitSessionStatus(loggedIn.value)).toBe(200);
  expect(await page.evaluate(async email => (await fetch("/api/v1/auth/login", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "incorrect-password" }),
  })).status, email)).toBe(401);
  expect(await splitSessionStatus(loggedIn.value)).toBe(401);
  expect(await page.evaluate(async () => (await fetch("/api/v1/tally/overview")).status)).toBe(401);
  await page.goto("/");
  await expect(page).toHaveURL(`${baseURL}/signin`);
});
