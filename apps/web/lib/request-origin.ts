/** The browser-facing origin, with TLS termination reported by the reverse proxy. */
export function requestOrigin(request: Request): URL {
  const url = new URL(request.url);
  const protocol = request.headers.get("x-forwarded-proto") ?? url.protocol.slice(0, -1);
  // Use the actual Host header; a client-supplied forwarded host must not bypass CSRF checks.
  const host = request.headers.get("host") ?? url.host;
  if (!["http", "https"].includes(protocol) || /[/\\?#@,\s]/.test(host)) {
    throw new Error("Invalid request authority");
  }
  return new URL(`${protocol}://${host}`);
}

export function isSameOrigin(request: Request, origin = requestOrigin(request)): boolean {
  return request.headers.get("origin") === origin.origin
    && request.headers.get("sec-fetch-site") !== "cross-site";
}
