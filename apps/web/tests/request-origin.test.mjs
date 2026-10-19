import assert from "node:assert/strict";
import { test } from "node:test";
import { isSameOrigin, requestOrigin } from "../lib/request-origin.ts";

function request(host, origin, extra = {}) {
  return new Request("http://web:3003/api/v1/auth/register", {
    method: "POST",
    headers: { host, "x-forwarded-proto": "https", ...(origin ? { origin } : {}), ...extra },
  });
}

test("HTTPS mutations accept the requested domain or IP without environment configuration", () => {
  for (const host of ["tally.godel-labs.ai", "another.example", "192.0.2.10", "localhost", "tally.example:8443", "[::1]:8443"]) {
    const incoming = request(host, `https://${host}`);
    assert.equal(requestOrigin(incoming).origin, `https://${host}`);
    assert.equal(isSameOrigin(incoming), true);
  }
});

test("direct development requests use their own HTTP origin", () => {
  const incoming = new Request("http://localhost:8080/api/v1/auth/register", {
    headers: { origin: "http://localhost:8080" },
  });
  assert.equal(isSameOrigin(incoming), true);
});

test("mutations reject cross-origin, missing, opaque, and wrong-port origins", () => {
  for (const origin of ["https://attacker.example", "https://tally.godel-labs.ai:8443", "http://tally.godel-labs.ai", "null", undefined]) {
    assert.equal(isSameOrigin(request("tally.godel-labs.ai", origin)), false);
  }
  assert.equal(isSameOrigin(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", {
    "sec-fetch-site": "cross-site",
  })), false);
});

test("client-supplied forwarded hosts cannot authorize a different origin", () => {
  const incoming = request("tally.godel-labs.ai", "https://attacker.example", {
    "x-forwarded-host": "attacker.example",
  });
  assert.equal(requestOrigin(incoming).origin, "https://tally.godel-labs.ai");
  assert.equal(isSameOrigin(incoming), false);
});

test("malformed authorities and forwarded protocols are rejected", () => {
  for (const host of ["attacker.example/path", "user@tally.godel-labs.ai", "tally.godel-labs.ai,attacker.example", "tally.godel-labs.ai?query", "tally.godel-labs.ai\\path"]) {
    assert.throws(() => requestOrigin(request(host, "https://tally.godel-labs.ai")));
  }
  for (const protocol of ["ftp", "https,http"]) {
    assert.throws(() => requestOrigin(request("tally.godel-labs.ai", "https://tally.godel-labs.ai", {
      "x-forwarded-proto": protocol,
    })));
  }
});
