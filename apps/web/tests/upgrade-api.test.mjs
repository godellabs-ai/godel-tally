import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { upgradeApi, isTransientUpgradeError } from "../lib/upgrade.ts";

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

test("upgrade calls use the host proxy with bounded requests", async () => {
  const calls = [];
  globalThis.fetch = async (url, options) => {
    assert.ok(options.signal instanceof AbortSignal);
    assert.equal(options.cache, "no-store");
    calls.push({ url, method: options.method, body: options.body });
    return Response.json({ status: "staging" });
  };
  await upgradeApi("status");
  await upgradeApi("prepare", { approved: true });
  assert.deepEqual(calls, [
    { url: "/api/upgrade/status", method: "GET", body: undefined },
    { url: "/api/upgrade/prepare", method: "POST", body: '{"approved":true}' },
  ]);
});

test("dropped connections and gateway responses remain retryable during cutover", async () => {
  globalThis.fetch = async () => { throw new TypeError("Failed to fetch"); };
  assert.ok(isTransientUpgradeError(await upgradeApi("status").catch(error => error)));
  globalThis.fetch = async () => new Response("<html>Bad Gateway</html>", { status: 502 });
  assert.ok(isTransientUpgradeError(await upgradeApi("status").catch(error => error)));
  globalThis.fetch = async () => Response.json({ error: "Review required" }, { status: 409 });
  const conflict = await upgradeApi("prepare", {}).catch(error => error);
  assert.equal(conflict.message, "Review required");
  assert.equal(isTransientUpgradeError(conflict), false);
});
