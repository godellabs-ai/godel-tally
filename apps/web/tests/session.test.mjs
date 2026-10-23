import assert from "node:assert/strict";
import { test } from "node:test";
import { sourceModule } from "./source-module.mjs";

const { safeReturnPath, authFetch } = sourceModule("lib/session.ts");
const origin = "https://tally.example.test";

test("return paths normalize browser URLs before rejecting external navigation", () => {
  for (const next of [null, "https://other.example", "javascript:alert(1)", "//other.example", "/\\other.example", "/\t/other.example", "/\n/other.example", "/\r/other.example", "/signin?next=/users", "/users/../signin", "/%2e%2e/signin", "/.//other.example", "//[invalid"]) {
    assert.equal(safeReturnPath(next, origin), "/", JSON.stringify(next));
  }
  assert.equal(safeReturnPath("/users?filter=active#invites", origin), "/users?filter=active#invites");
  assert.equal(safeReturnPath("/registry/../users", origin), "/users");
});

test("account expiry preserves the full return view and respects host authentication", async () => {
  const originalFetch = globalThis.fetch, originalWindow = globalThis.window;
  const redirects = [];
  let token = null;
  globalThis.window = { location: { origin, pathname: "/users", search: "?filter=active", hash: "#invites", assign: url => redirects.push(url) }, localStorage: { getItem: () => token } };
  try {
    globalThis.fetch = async () => Response.json({ error: "Session expired" }, { status: 401 });
    assert.equal((await authFetch("invitations", { method: "POST" })).status, 401);
    assert.deepEqual(redirects, [`${origin}/signin?next=%2Fusers%3Ffilter%3Dactive%23invites`]);
    token = "host-token";
    await authFetch("me");
    assert.equal(redirects.length, 1);
    token = null;
    globalThis.fetch = async () => Response.json({ error: "Current password is incorrect" }, { status: 400 });
    await authFetch("me/password", { method: "POST" });
    assert.equal(redirects.length, 1);
  } finally { globalThis.fetch = originalFetch; globalThis.window = originalWindow; }
});
