import assert from "node:assert/strict";
import { test } from "node:test";
import { isTransientUsersError, loadUsers } from "../lib/users.ts";

test("users data recovers after dropped connections and gateway responses", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const status of [0, 502, 503, 504]) {
      globalThis.fetch = async () => {
        if (!status) throw new TypeError("Failed to fetch");
        return new Response("<html>Gateway unavailable</html>", { status });
      };
      const failure = await loadUsers().catch(cause => cause);
      assert.ok(isTransientUsersError(failure));
      assert.match(failure.message, /reconnecting/);
    }
    globalThis.fetch = async (url, options) => {
      assert.ok(options.signal instanceof AbortSignal);
      return Response.json(url.endsWith("/users") ? { users: [{ id: "admin" }] } : { user: { id: "admin" } });
    };
    assert.deepEqual(await loadUsers(), { users: [{ id: "admin" }], currentUserId: "admin" });
  } finally { globalThis.fetch = originalFetch; }
});

test("authorization failures are distinct from transient outages", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const [status, message] of [[401, /Sign in/], [403, /Administrator/]]) {
      globalThis.fetch = async () => new Response("{}", { status });
      const failure = await loadUsers().catch(cause => cause);
      assert.equal(isTransientUsersError(failure), false);
      assert.match(failure.message, message);
    }
  } finally { globalThis.fetch = originalFetch; }
});

test("cancelling users loading does not become a reconnect error", async () => {
  const originalFetch = globalThis.fetch;
  try {
    const controller = new AbortController(); controller.abort();
    globalThis.fetch = async (url, options) => { throw options.signal.reason; };
    const failure = await loadUsers(controller.signal).catch(cause => cause);
    assert.equal(failure, controller.signal.reason);
    assert.equal(isTransientUsersError(failure), false);
  } finally { globalThis.fetch = originalFetch; }
});
