// Local fixture for the web proxy's upgrade-cleanup test. Never starts host actions.
// Run with: node tests/fixtures/host-server.mjs
import { createServer } from "node:http";
const token = "e".repeat(64);
createServer((request, response) => {
  response.setHeader("content-type", "application/json");
  if (request.url === "/pair") return response.end(JSON.stringify({ token }));
  if (request.url === "/upgrade/cleanup" && request.headers.authorization === `Bearer ${token}`) {
    return response.end(JSON.stringify({ cleaned: false, status: "not_started" }));
  }
  response.statusCode = request.headers.authorization ? 404 : 401;
  response.end(JSON.stringify({ error: "Unsupported test request" }));
}).listen(Number(process.env.TALLY_E2E_HOST_PORT ?? 18898), "127.0.0.1");
