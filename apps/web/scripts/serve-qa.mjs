// Isolated static UI fixture server. API calls must be intercepted by Playwright.
// This intentionally has no backend or authentication and only binds loopback.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";

const root = resolve("out");
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".gif": "image/gif", ".ico": "image/x-icon", ".woff2": "font/woff2", ".txt": "text/plain" };
createServer(async (request, response) => {
  const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  const file = resolve(root, `.${pathname === "/" ? "/index.html" : pathname}`);
  if (!file.startsWith(root + sep) || pathname.startsWith("/api/")) {
    response.writeHead(404).end();
    return;
  }
  for (const candidate of [file, `${file}.html`]) {
    try {
      const body = await readFile(candidate);
      response.writeHead(200, { "Content-Type": types[extname(candidate)] ?? "application/octet-stream" }).end(body);
      return;
    } catch { /* Try the static HTML route. */ }
  }
  response.writeHead(404).end();
}).listen(18081, "127.0.0.1");
