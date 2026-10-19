import { expect, test, type Page } from "@playwright/test";

type UpgradeReceipt = {
  cutover_stage?: string; cutover_retryable?: boolean; final_url?: string; temporary_url?: string; failure_reason?: string; migration_warning?: string;
  requested_gate_dir?: string; progress?: { at: string; message: string }[]; attempt_log?: { name: string; content: string; truncated: boolean };
};

async function mockUpgrade(page: Page, initialStatus = "not_started", receipt: UpgradeReceipt = {}, admin = true) {
  let currentStatus = initialStatus;
  let currentReceipt = receipt;
  let requestedFinalUrl = initialStatus === "not_started" ? null : "https://gate.example.test";
  const requests: { path: string; body: unknown }[] = [];
  if (!process.env.TALLY_E2E_STORAGE_STATE) await page.context().addCookies([{ name: "tally_session", value: "upgrade-test-session", url: test.info().project.use.baseURL! }]);
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { user: { role: admin ? "admin" : "member", email: "admin@example.test" } } }));
  await page.route("**/api/upgrade/**", async route => {
    const path = new URL(route.request().url()).pathname.replace("/api/upgrade/", "");
    const body = route.request().postDataJSON();
    requests.push({ path, body });
    if (path === "status") return route.fulfill({ json: {
      status: currentStatus, busy: false, progress: [], version: "0.1.0",
      suggested_gate_dir: "/tmp/godel-gate", requested_final_url: requestedFinalUrl,
      temporary_url: null, ...currentReceipt,
    } });
    if (path === "preview") return route.fulfill({ json: {
      temporary_url: "https://gate.example.test:8443", version: "0.1.0", installer_sha256: "test-checksum",
      expires_at: null, digest: "test-digest", effects: ["Transfer Tally data to Gate for review"],
    } });
    if (path === "prepare" || path === "cutover") {
      requestedFinalUrl = body.final_url;
      currentStatus = path === "prepare" ? "staging" : "cutting_over";
      return route.fulfill({ json: { status: currentStatus } });
    }
    if (path === "reset") { currentStatus = "not_started"; currentReceipt = {}; requestedFinalUrl = null; return route.fulfill({ json: {} }); }
    return route.fulfill({ status: 404, json: { error: `Unexpected test request: ${path}` } });
  });
  await page.goto("/upgrade");
  return requests;
}

test("upgrade uses one details form and starts only after installation review", async ({ page }) => {
  const apiRequests: string[] = [];
  page.on("request", request => { if (request.url().includes("/api/")) apiRequests.push(new URL(request.url()).pathname); });
  const requests = await mockUpgrade(page);
  await expect(page.getByRole("form", { name: "Upgrade details" })).toBeVisible();
  await expect(page.getByLabel("Gate install directory", { exact: true })).toHaveValue("/tmp/godel-gate");
  await page.getByLabel("Registration key", { exact: false }).fill("gg_private_fixture_key");
  await page.getByLabel("Final Gate Console URL", { exact: true }).fill("https://gate.example.test");
  await expect(page.locator("textarea")).toHaveCount(0);
  await expect(page.getByText(/OpenAI|Anthropic|Claude|New chat|Live review/i)).toHaveCount(0);
  await page.getByRole("button", { name: "Review upgrade", exact: true }).click();
  await expect(page.getByRole("region", { name: "Installation review" })).toBeVisible();
  expect(requests.find(request => request.path === "preview")?.body).toEqual({
    registration_key: "gg_private_fixture_key", final_url: "https://gate.example.test", gate_dir: "/tmp/godel-gate",
  });
  expect(requests.filter(request => request.path === "prepare")).toHaveLength(0);
  // Editing details invalidates the reviewed digest and requires a fresh review.
  await page.getByLabel("Gate install directory", { exact: true }).fill("/tmp/new-gate");
  await expect(page.getByRole("button", { name: "Upgrade to Gate", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Review upgrade", exact: true }).click();
  await page.getByRole("button", { name: "Upgrade to Gate", exact: true }).click();
  await expect(page.getByRole("progressbar")).toBeVisible();
  expect(requests.find(request => request.path === "prepare")?.body).toEqual({
    registration_key: "gg_private_fixture_key", final_url: "https://gate.example.test", gate_dir: "/tmp/new-gate",
    version: "0.1.0", installer_sha256: "test-checksum", digest: "test-digest", approved: true,
  });
  expect(apiRequests.every(path => path === "/api/v1/auth/me" || path.startsWith("/api/upgrade/"))).toBe(true);
});

test("upgrade details stay editable while the host service reconnects", async ({ page }) => {
  await mockUpgrade(page);
  await page.route("**/api/upgrade/**", route => route.fulfill({ status: 503, json: { error: "Upgrade service unavailable" } }));
  await page.reload();
  await expect(page.getByText("The upgrade service is connecting.", { exact: false })).toBeVisible();
  await page.getByLabel("Registration key", { exact: false }).fill("gg_private_fixture_key");
  await page.getByLabel("Final Gate Console URL", { exact: true }).fill("https://gate.example.test");
  await page.getByLabel("Gate install directory", { exact: true }).fill("/tmp/gate");
  await expect(page.getByRole("button", { name: "Review upgrade", exact: true })).toBeDisabled();
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

test("members cannot enter upgrade details or call the host service", async ({ page }) => {
  const requests = await mockUpgrade(page, "not_started", {}, false);
  await expect(page.getByText("Sign in as a Tally administrator to upgrade this installation.")).toBeVisible();
  await expect(page.getByRole("form")).toHaveCount(0);
  expect(requests).toHaveLength(0);
});

test("Gate review allows editing the final URL before TLS and uses it for the approved switch", async ({ page }) => {
  await mockUpgrade(page, "ready_for_cutover");
  const finalUrl = page.getByLabel("Final Gate Console URL", { exact: true });
  await expect(finalUrl).toHaveValue("https://gate.example.test");
  await expect(page.getByLabel("Production TLS full-chain path on this host")).toHaveCount(0);
  await finalUrl.fill("https://console.example.test:9443");
  const approveSwitch = page.getByRole("button", { name: "Approve switch to Gate at https://console.example.test:9443", exact: true });
  await expect(approveSwitch).toBeDisabled();
  await page.getByLabel("I signed in and reviewed Gate").check();
  await expect(approveSwitch).toBeDisabled();
  await page.getByLabel("Production TLS full-chain path on this host").fill("/tmp/fullchain.pem");
  await page.getByLabel("Production TLS private-key path on this host").fill("/tmp/privkey.pem");
  await expect(approveSwitch).toBeEnabled();
  const request = page.waitForRequest(request => request.url().endsWith("/api/upgrade/cutover"));
  await approveSwitch.click();
  expect((await request).postDataJSON()).toEqual({
    final_url: "https://console.example.test:9443", tls_cert: "/tmp/fullchain.pem", tls_key: "/tmp/privkey.pem", approved: true,
  });
  await expect(page.getByRole("link", { name: "https://console.example.test:9443", exact: true })).toBeVisible();
});

test("Tally shutdown failure shows the verified final Gate URL without offering another switch", async ({ page }) => {
  await mockUpgrade(page, "cutover_failed", {
    cutover_stage: "retiring_tally", cutover_retryable: false,
    final_url: "https://gate.example.test", temporary_url: "https://gate.example.test:8443",
    failure_reason: "Gate HTTPS is healthy, but Tally shutdown needs attention; Gate remains running",
  });
  await expect(page.getByText("Tally shutdown needs attention", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "https://gate.example.test", exact: true })).toHaveAttribute("href", "https://gate.example.test");
  await expect(page.getByText("Gate passed its final HTTPS and service checks.", { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "https://gate.example.test:8443", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Retry switch|Cancel and resume Tally/ })).toHaveCount(0);
});

test("incomplete router recovery does not advertise the Gate review console as available", async ({ page }) => {
  await mockUpgrade(page, "cutover_failed", {
    cutover_stage: "recovery_failed", cutover_retryable: false,
    temporary_url: "https://gate.example.test:8443",
  });
  await expect(page.getByText("This switch needs a recovery review before another attempt.", { exact: false })).toBeVisible();
  await expect(page.getByRole("link", { name: "https://gate.example.test:8443", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: /Retry switch|Cancel and resume Tally/ })).toHaveCount(0);
});

test("migration mismatch warns and still offers Gate review and cutover", async ({ page }) => {
  const warning = "PostgreSQL migrations differ (Tally 18, Gate 17); continuing with best-effort data transfer.";
  await mockUpgrade(page, "ready_for_cutover", {
    temporary_url: "https://gate.example.test:8443", migration_warning: warning,
  });
  await expect(page.getByText("Best-effort data transfer", { exact: true })).toBeVisible();
  await expect(page.getByText(warning, { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "https://gate.example.test:8443", exact: true })).toBeVisible();
  await page.getByLabel("I signed in and reviewed Gate").check();
  await page.getByLabel("Production TLS full-chain path on this host").fill("/tmp/fullchain.pem");
  await page.getByLabel("Production TLS private-key path on this host").fill("/tmp/privkey.pem");
  await expect(page.getByRole("button", { name: "Approve switch to Gate at https://gate.example.test", exact: true })).toBeEnabled();
});

test("a failed installation clears its logs and details before a fresh attempt", async ({ page }) => {
  const requests = await mockUpgrade(page, "failed", {
    failure_reason: "Gate PostgreSQL staging failed; inspect prepare.log and the Gate Postgres container log",
    requested_gate_dir: "/tmp/failed-gate",
    progress: [{ at: "2026-10-16T19:59:21Z", message: "Starting the Gate import database" }],
    attempt_log: { name: "prepare.log", content: "gate-postgres exited", truncated: false },
  });
  await expect(page.getByText("Installation stopped before cutover", { exact: true })).toBeVisible();
  await expect(page.getByText("Upgrade activity", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Gate install directory", { exact: true })).toHaveValue("/tmp/failed-gate");
  await page.getByLabel("Registration key", { exact: false }).fill("gg_private_fixture_key");
  await page.getByLabel("Final Gate Console URL", { exact: true }).fill("https://other.example.test");
  await page.getByRole("button", { name: "Clear logs and start over", exact: true }).click();
  await expect(page.getByText("Installation stopped before cutover", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Upgrade activity", { exact: true })).toHaveCount(0);
  await expect(page.getByText("prepare.log · redacted", { exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Registration key", { exact: false })).toHaveValue("");
  await expect(page.getByLabel("Gate install directory", { exact: true })).toHaveValue("/tmp/godel-gate");
  const defaultUrl = new URL(page.url());
  defaultUrl.protocol = "https:";
  defaultUrl.port = "";
  await expect(page.getByLabel("Final Gate Console URL", { exact: true })).toHaveValue(defaultUrl.origin);
  expect(requests.filter(request => request.path === "reset")).toHaveLength(1);
});
