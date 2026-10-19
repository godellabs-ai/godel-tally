import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import { test } from "node:test";

// Resolve Next.js's extensionless imports and app alias for Node's TypeScript loader.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "next/server") return nextResolve("next/server.js", context);
    if (specifier === "@/lib/request-origin") {
      return { url: new URL("../lib/request-origin.ts", import.meta.url).href, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

const auth = await import("../app/api/v1/auth/[[...path]]/route.ts");
const tally = await import("../app/api/v1/tally/[[...path]]/route.ts");
const upgrade = await import("../app/api/upgrade/[[...path]]/route.ts");

function request(host, origin, headers = {}, method = "POST") {
  return new Request("http://web:3003/api/v1/auth/register", {
    method,
    headers: { host, "x-forwarded-proto": "https", ...(origin ? { origin } : {}), ...headers },
    ...(method === "POST" ? { body: "{}" } : {}),
  });
}

test("actual auth and API proxies accept same-origin mutations with a different TALLY_URL", async () => {
  const originalFetch = globalThis.fetch;
  const originalUrl = process.env.TALLY_URL;
  process.env.TALLY_URL = "https://localhost";
  try {
    for (const proxy of [auth, tally]) {
      for (const host of ["tally.godel-labs.ai", "192.0.2.10", "another.example:8443"]) {
        let forwarded;
        globalThis.fetch = async (target, options) => {
          forwarded = options.headers;
          assert.notEqual(new URL(target).host, host);
          return new Response('{"accepted":true}', { status: 200 });
        };
        const response = await proxy.POST(request(host, `https://${host}`, {
          "x-forwarded-host": "attacker.example",
        }), { params: Promise.resolve({ path: ["register"] }) });
        assert.equal(response.status, 200);
        assert.deepEqual(await response.json(), { accepted: true });
        assert.equal(forwarded.get("origin"), `https://${host}`);
        assert.equal(forwarded.get("x-forwarded-host"), host);
        assert.equal(forwarded.get("x-forwarded-proto"), "https");
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
    if (originalUrl === undefined) delete process.env.TALLY_URL;
    else process.env.TALLY_URL = originalUrl;
  }
});

test("actual proxies reject CSRF attempts before contacting the backend", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("Rejected requests must not reach upstream"); };
  try {
    for (const proxy of [auth, tally]) {
      for (const origin of ["https://attacker.example", "https://tally.godel-labs.ai:8443", "null", undefined]) {
        const response = await proxy.POST(request("tally.godel-labs.ai", origin, {
          "x-forwarded-host": "attacker.example",
        }), { params: Promise.resolve({ path: ["register"] }) });
        assert.equal(response.status, 403);
        assert.deepEqual(await response.json(), { error: "Invalid request origin" });
      }
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("auth GET requests forward the public origin and preserve session cookies", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target, options) => {
    assert.equal(options.headers.get("x-forwarded-host"), "tally.godel-labs.ai");
    assert.equal(options.headers.get("x-forwarded-proto"), "https");
    const headers = new Headers();
    headers.append("set-cookie", "tally_session=fixture; Secure; HttpOnly");
    headers.append("set-cookie", "tally_auxiliary=fixture; Secure; HttpOnly");
    return new Response("{}", { headers });
  };
  try {
    const response = await auth.GET(request("tally.godel-labs.ai", undefined, {}, "GET"), {
      params: Promise.resolve({ path: ["me"] }),
    });
    assert.equal(response.status, 200);
    assert.equal(response.headers.getSetCookie().length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Upgrade host operations require an administrator and keep the host bearer server-side", async () => {
  const originalFetch = globalThis.fetch;
  const originalCode = process.env.TALLY_UPGRADE_BOOTSTRAP_CODE;
  process.env.TALLY_UPGRADE_BOOTSTRAP_CODE = "c".repeat(64);
  const token = "d".repeat(64);
  let role = "member";
  const upstream = [];
  globalThis.fetch = async (target, options) => {
    const url = new URL(target);
    if (url.pathname.endsWith("/me")) return Response.json({ user: { role } });
    if (url.pathname === "/pair") return Response.json({ token });
    upstream.push({ url, headers: new Headers(options.headers) });
    return Response.json({ status: "not_started" });
  };
  const send = () => upgrade.GET(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", { cookie: "tally_session=browser" }, "GET"), {
    params: Promise.resolve({ path: ["status"] }),
  });
  try {
    assert.equal((await send()).status, 403);
    assert.equal(upstream.length, 0);
    role = "admin";
    const response = await send();
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "not_started");
    const forwarded = upstream.at(-1);
    assert.equal(forwarded.url.pathname, "/upgrade");
    assert.equal(forwarded.headers.get("Origin"), process.env.TALLY_UPGRADE_WEB_ORIGIN ?? "http://127.0.0.1:8080");
    assert.equal(forwarded.headers.get("Authorization"), `Bearer ${token}`);
    assert.equal(forwarded.headers.get("cookie"), null);
    const preview = await upgrade.POST(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", { cookie: "tally_session=browser" }), {
      params: Promise.resolve({ path: ["preview"] }),
    });
    assert.equal(preview.status, 200);
    assert.equal(upstream.at(-1).url.pathname, "/upgrade/preview");
    const count = upstream.length;
    const crossOrigin = await upgrade.POST(request("tally.godel-labs.ai", "https://attacker.example", { cookie: "tally_session=browser" }), {
      params: Promise.resolve({ path: ["prepare"] }),
    });
    assert.equal(crossOrigin.status, 403);
    assert.equal(upstream.length, count);
    const removedActions = await upgrade.GET(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", { cookie: "tally_session=browser" }, "GET"), {
      params: Promise.resolve({ path: ["actions"] }),
    });
    assert.equal(removedActions.status, 404);
    const unknown = await upgrade.GET(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", { cookie: "tally_session=browser" }, "GET"), {
      params: Promise.resolve({ path: ["internal", "context"] }),
    });
    assert.equal(unknown.status, 404);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalCode === undefined) delete process.env.TALLY_UPGRADE_BOOTSTRAP_CODE; else process.env.TALLY_UPGRADE_BOOTSTRAP_CODE = originalCode;
  }
});

const { proxy } = await import("../proxy.ts");
const { NextRequest } = await import("next/server");

test("page and API access fail closed for absent, invalid, and unavailable sessions", async () => {
  const originalFetch = globalThis.fetch;
  const protectedPaths = ["/", "/overview", "/findings", "/users", "/settings", "/upgrade", "/api/v1/tally/overview", "/api/upgrade/status"];
  try {
    for (const path of protectedPaths) {
      const make = cookie => new NextRequest(`https://tally.example.test${path}`, { headers: cookie ? { cookie } : {} });
      globalThis.fetch = async () => { throw new Error("No cookie must not contact auth"); };
      const missing = await proxy(make());
      assert.equal(missing.status, path.startsWith("/api/") ? 401 : 307);
      for (const status of [401, 403]) {
        globalThis.fetch = async () => new Response("{}", { status });
        const invalid = await proxy(make("tally_session=" + "f".repeat(64)));
        assert.equal(invalid.status, path.startsWith("/api/") ? 401 : 307);
      }
      globalThis.fetch = async () => new Response("{}", { status: 503 });
      assert.equal((await proxy(make("tally_session=" + "f".repeat(64)))).status, 503);
      globalThis.fetch = async () => Response.json({ user: { role: "member" } });
      assert.equal((await proxy(make("tally_session=" + "f".repeat(64)))).status, 200);
    }
  } finally { globalThis.fetch = originalFetch; }
});
