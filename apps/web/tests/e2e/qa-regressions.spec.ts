import { expect, test, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { fixture } from "../fixtures/estate";
import { findingsFixture } from "../fixtures/findings";
import { eventStreamFixture } from "../fixtures/event-stream";

const admin = { id: "qa-admin", email: "admin@example.test", display_name: "QA Admin", first_name: "QA", last_name: "Admin", role: "admin", disabled: false, has_password: true };
const member = { ...admin, id: "qa-member", email: "member@example.test", display_name: "QA Member", role: "member" };

test("sign-in return URLs cannot leave Tally after browser normalization", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/auth/status", route => route.fulfill({ json: { first_user_registration_open: false, email_configured: false, user: admin } }));
  const external: string[] = [];
  await page.route("**://example.invalid/**", route => { external.push(route.request().url()); return route.fulfill({ body: "Unexpected external navigation" }); });
  for (const next of ["/\t/example.invalid/review", "/\n/example.invalid/review", "/\\example.invalid/review", "//example.invalid/review", "/.//example.invalid/review"]) {
    await page.goto(`/signin?next=${encodeURIComponent(next)}`);
    await page.getByRole("button", { name: "Continue to Tally" }).click();
    await expect(page).toHaveURL(new URL("/", page.url()).href);
    expect(external).toEqual([]);
  }
});

test("successful sign-in preserves a local return path including query and fragment", async ({ page }) => {
  await setup(page);
  await page.goto(`/signin?next=${encodeURIComponent("/users?filter=active#invites")}`);
  await page.getByLabel("Email", { exact: true }).fill(admin.email);
  await page.getByLabel("Password", { exact: true }).fill("fixture-password-123");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/users\?filter=active#invites$/);
});

test("Settings redirects an expired session even when the shell cached the user", async ({ page }) => {
  await setup(page); await page.goto("/users");
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(navigation.getByRole("link", { name: "Settings", exact: true })).toBeVisible();
  await page.route("**/api/v1/auth/me", route => route.fulfill({ status: 401, json: { error: "Session expired" } }));
  await navigation.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page).toHaveURL(/\/signin\?next=%2Fsettings$/);
});

test("Users mutations redirect expired sessions with their complete return view", async ({ page }) => {
  await setup(page); await page.goto("/users?filter=active#invites");
  await expect(page.getByText("QA Admin", { exact: true })).toBeVisible();
  await page.route("**/api/v1/auth/invitations", route => route.request().method() === "POST"
    ? route.fulfill({ status: 401, json: { error: "Session expired" } }) : route.fallback());
  await page.getByLabel("Email address", { exact: true }).fill("invitee@example.test");
  await page.getByRole("button", { name: "Create invitation" }).click();
  await expect(page).toHaveURL(/\/signin\?next=%2Fusers%3Ffilter%3Dactive%23invites$/);
});

test("an incorrect current password stays a form error without ending the session", async ({ page }) => {
  await setup(page); await page.goto("/users");
  await page.route("**/api/v1/auth/me/password", route => route.fulfill({ status: 400, json: { error: "Current password is incorrect" } }));
  await page.getByRole("button", { name: "Change password", exact: true }).click();
  await page.getByLabel("Current password", { exact: true }).fill("wrong-password-123");
  await page.getByLabel("New password", { exact: true }).fill("changed-password-123");
  await page.getByLabel("Confirm new password", { exact: true }).fill("changed-password-123");
  await page.getByRole("button", { name: "Save password", exact: true }).click();
  await expect(page.getByRole("main").getByRole("alert").first()).toContainText("Current password is incorrect");
  await expect(page).toHaveURL(/\/users$/);
});

test("email settings mutations return expired sessions to sign-in", async ({ page }) => {
  await setup(page);
  await page.route("**/api/v1/auth/email", route => route.request().method() === "POST"
    ? route.fulfill({ status: 401, json: { error: "Session expired" } })
    : route.fulfill({ json: { configured: true, enabled: true, source: "database", provider: "resend", from_email: "tally@example.test", from_name: null, settings: {}, secrets_set: ["api_key"], public_url_configured: true } }));
  await page.goto("/settings");
  await page.getByRole("button", { name: "Save email settings" }).click();
  await expect(page).toHaveURL(/\/signin\?next=%2Fsettings$/);
});

test("admin navigation retries temporary account lookup failures without reload", async ({ page }) => {
  await setup(page); await page.clock.install();
  let calls = 0;
  await page.route("**/api/v1/auth/me", route => ++calls === 1 ? route.fulfill({ status: 503, body: "Unavailable" })
    : calls === 2 ? route.abort("failed") : route.fulfill({ json: { user: admin } }));
  await page.goto("/registry");
  const users = page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: "Users", exact: true });
  await expect.poll(() => calls).toBe(1);
  await expect(users).toHaveCount(0);
  await page.clock.fastForward(5000);
  await expect.poll(() => calls).toBe(2);
  await page.clock.fastForward(5000);
  await expect(users).toBeVisible();
  await page.clock.fastForward(30_000);
  expect(calls).toBe(3);
});

test("navigation recovers a failed account lookup before its retry timer", async ({ page }) => {
  await setup(page); await page.clock.install();
  let calls = 0;
  await page.route("**/api/v1/auth/me", route => ++calls === 1 ? route.fulfill({ status: 503, body: "Unavailable" }) : route.fulfill({ json: { user: admin } }));
  await page.goto("/registry");
  const navigation = page.getByRole("navigation", { name: "Primary navigation" });
  await expect(page.getByText("Provider 0", { exact: true })).toBeVisible();
  await expect(navigation.getByRole("link", { name: "Users", exact: true })).toHaveCount(0);
  await navigation.getByRole("link", { name: "Connectors", exact: true }).click();
  await expect(navigation.getByRole("link", { name: "Users", exact: true })).toBeVisible();
  expect(calls).toBe(2);
});

async function setup(page: Page) {
  await page.route("**/api/v1/auth/**", route => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path.endsWith("/status") ? { first_user_registration_open: false, email_configured: false, user: null }
      : path.endsWith("/users") ? { users: [admin, member] }
      : path.endsWith("/invitations") ? { invitations: [] } : { user: admin } });
  });
  await page.route("**/api/v1/tally/**", route => {
    const url = new URL(route.request().url()), path = url.pathname;
    return route.fulfill({ json: path.endsWith("/registry/providers") ? Array.from({ length: 36 }, (_, i) => ({
      provider_id: `p${i}`, key: `provider${i}`, name: `Provider ${i}`, category: "direct_provider", country_code: "US", catalog: true,
      sanctioned: false, model_count: 0, finding_count: 0, last_used_at: null,
    })) : path.endsWith("/registry/models") ? [] : path.endsWith("/registry/provider-domains") ? {}
      : path.endsWith("/estate") ? fixture() : path.endsWith("/findings") ? findingsFixture()
      : path.endsWith("/event-stream") ? eventStreamFixture(url.searchParams) : { items: [], jobs: [] } });
  });
}

for (const theme of ["light", "dark"]) {
  for (const path of ["registry", "connectors", "users"]) {
    test(`${path} accessibility in ${theme} mode (007, 020, 029)`, async ({ page }, info) => {
      await setup(page);
      await page.addInitScript(theme => localStorage.setItem("tally-theme", theme), theme);
      await page.goto(`/${path}`);
      if (theme === "dark") await expect(page.locator("html")).toHaveClass(/dark/);
      if (path === "registry") {
        await expect(page.getByRole("checkbox")).toHaveCount(37);
        await expect(page.getByRole("checkbox", { name: "Select Provider 0", exact: true })).toBeVisible();
        await expect(page.getByText(/does not block/)).toBeVisible();
      } else if (path === "connectors") {
        await expect(page.getByRole("heading", { name: "OpenAI Agents", exact: true })).toBeVisible();
      } else {
        await expect(page.getByText("QA Admin", { exact: true })).toBeVisible();
      }
      // Hydration animates the theme. Measure the settled colors, not a frame
      // interpolated between light and dark palettes.
      await page.evaluate(async () => {
        await Promise.all(document.getAnimations().filter(animation => animation instanceof CSSTransition).map(animation => animation.finished.catch(() => {})));
      });
      const results = await new AxeBuilder({ page }).withRules(["label", "empty-table-header", "heading-order", "color-contrast"]).analyze();
      await info.attach("axe.json", { body: JSON.stringify(results, null, 2), contentType: "application/json" });
      expect(results.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, summary: n.failureSummary })) }))).toEqual([]);
    });
  }
}

test("connector dialogs return focus to each invoking button (019)", async ({ page }) => {
  await setup(page); await page.goto("/connectors");
  for (const name of ["OpenAI Agents", "ServiceNow AI Agents", "OpenAI Agents"]) {
    const opener = page.locator(".card-surface").filter({ has: page.getByRole("heading", { name, exact: true }) }).getByRole("button", { name: /Configure|Connect/ }).first();
    await opener.focus(); await page.keyboard.press("Enter");
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("dialog")).toHaveCount(0);
    await expect(opener).toBeFocused();
  }
});

test("sign-in loads once without anonymous 401 or polling (027)", async ({ page }) => {
  await setup(page); await page.clock.install();
  const requests: string[] = [], errors: string[] = [];
  page.on("request", request => { if (request.url().includes("/api/v1/auth/")) requests.push(new URL(request.url()).pathname); });
  page.on("console", message => { if (message.type() === "error") errors.push(message.text()); });
  await page.goto("/signin");
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeEnabled();
  await page.clock.fastForward(30_000);
  expect(requests).toEqual(["/api/v1/auth/status"]);
  expect(errors).toEqual([]);
});

test("sign-in retries a transient status outage and then stops", async ({ page }) => {
  await setup(page); await page.clock.install();
  let calls = 0;
  await page.route("**/api/v1/auth/status", route => ++calls === 1
    ? route.fulfill({ status: 503, json: { error: "unavailable" } })
    : route.fulfill({ json: { first_user_registration_open: false, email_configured: false, user: null } }));
  await page.goto("/signin");
  await expect(page.locator("form").getByRole("alert")).toContainText("Retrying");
  await page.clock.fastForward(6000);
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeEnabled();
  await page.clock.fastForward(30_000);
  expect(calls).toBe(2);
});

for (const status of [401, 403]) {
  test(`open page handles API ${status} (015, 016)`, async ({ page }) => {
    await setup(page);
    await page.route("**/api/v1/tally/audit**", route => route.fulfill({ status, json: { error: "denied" } }));
    await page.goto("/audit");
    if (status === 401) {
      await expect(page).toHaveURL(/\/signin\?next=%2Faudit/);
      await expect(page.getByRole("status")).toContainText("Your session ended");
    } else {
      await expect(page.getByRole("main").getByRole("alert")).toContainText("available to Tally administrators");
    }
  });
}

test("mobile overview remains scrollable and retains its loading space (018, 021)", async ({ page }, info) => {
  await setup(page); await page.setViewportSize({ width: 390, height: 844 });
  let ready!: () => void;
  const gate = new Promise<void>(resolve => { ready = resolve; });
  await page.route("**/api/v1/tally/findings", async route => { await gate; await route.fulfill({ json: findingsFixture() }); });
  await page.route("**/api/v1/tally/estate?**", async route => { await gate; await route.fulfill({ json: fixture() }); });
  await page.goto("/");
  const findings = page.getByRole("region", { name: "Overview findings" });
  await expect(page.getByText("Loading overview…")).toBeVisible();
  const before = (await findings.boundingBox())!.y;
  ready();
  const canvas = page.locator("[data-overview-canvas]");
  await expect(canvas.locator(".flow-node").first()).toBeVisible();
  await expect(page.getByText("Loading overview…")).toHaveCount(0);
  expect(Math.abs((await findings.boundingBox())!.y - before)).toBeLessThanOrEqual(1);
  const measured = await canvas.evaluate(element => {
    element.scrollLeft = element.scrollWidth;
    return { scrollLeft: element.scrollLeft, width: element.clientWidth, content: element.scrollWidth,
      fonts: [...element.querySelectorAll(".flow-txt strong, .flow-txt span")].map(node => parseFloat(getComputedStyle(node).fontSize)) };
  });
  expect(measured.scrollLeft).toBeGreaterThan(0);
  expect(measured.scrollLeft + measured.width).toBe(measured.content);
  expect(Math.min(...measured.fonts)).toBeGreaterThanOrEqual(12);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await info.attach("mobile-overview.png", { body: await page.screenshot({ fullPage: true, path: info.outputPath("verified.png") }), contentType: "image/png" });
});

test("mobile Users supports role invitations, revocation and promotion (006, 012, 024)", async ({ page }, info) => {
  await setup(page); await page.setViewportSize({ width: 390, height: 844 });
  let invitations: { id: string; email: string; role: string; expires_at: string; invited_by: string }[] = [];
  const people = [admin, { ...member }];
  await page.route("**/api/v1/auth/users", route => route.fulfill({ json: { users: people } }));
  const writes: { path: string; body: unknown }[] = [];
  await page.route("**/api/v1/auth/invitations**", async route => {
    const request = route.request();
    if (request.method() === "POST") {
      const body = request.postDataJSON(); writes.push({ path: "/invitations", body });
      invitations = [{ ...body, id: "invite-1", expires_at: "2030-01-01T00:00:00Z", invited_by: admin.email }];
      return route.fulfill({ json: { invite_url: "https://tally.example/signin#invite=fixture" } });
    }
    if (request.method() === "DELETE") { invitations = []; return route.fulfill({ status: 204 }); }
    return route.fulfill({ json: { invitations } });
  });
  await page.route("**/api/v1/auth/users/*/role", route => {
    people[1].role = route.request().postDataJSON().role;
    writes.push({ path: "/role", body: route.request().postDataJSON() });
    return route.fulfill({ status: 204 });
  });
  await page.goto("/users");
  await expect(page.getByText("QA Admin", { exact: true })).toBeVisible();
  await page.getByLabel("Email address", { exact: true }).fill("teammate.with.a.long.email.address@example.test");
  await page.getByRole("combobox", { name: /^Role/ }).selectOption("admin");
  await page.screenshot({ path: info.outputPath("mobile-invitation-role.png") });
  await page.getByRole("button", { name: "Create invitation", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Pending invitations" })).toBeVisible();
  const invitation = page.locator("section").filter({ has: page.getByRole("heading", { name: "Pending invitations" }) });
  expect(await invitation.locator("strong").evaluate(element => element.getBoundingClientRect().right - element.closest("section")!.getBoundingClientRect().right)).toBeLessThan(-18);
  expect(writes[0].body).toEqual({ email: "teammate.with.a.long.email.address@example.test", role: "admin" });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.getByRole("button", { name: /Revoke invitation for/ }).scrollIntoViewIfNeeded();
  await info.attach("mobile-users.png", { body: await page.screenshot({ fullPage: true, path: info.outputPath("verified.png") }), contentType: "image/png" });
  await page.setViewportSize({ width: 1360, height: 1000 });
  await page.getByRole("heading", { name: "Invite a user" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("desktop-users.png") });
  await page.getByRole("button", { name: /Revoke invitation for/ }).click();
  await expect(page.getByRole("heading", { name: "Pending invitations" })).toHaveCount(0);
  await page.getByRole("button", { name: "Make administrator", exact: true }).click();
  expect(writes.at(-1)).toEqual({ path: "/role", body: { role: "admin" } });
  await expect(page.getByRole("button", { name: "Make member", exact: true })).toBeVisible();
});
