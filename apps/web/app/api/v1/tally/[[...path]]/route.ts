import { NextResponse } from "next/server";
import { isSameOrigin, requestOrigin } from "@/lib/request-origin";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

type RouteContext = { params: Promise<{ path?: string[] }> };

const HOP_BY_HOP_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

function removeHopByHopHeaders(headers: Headers) {
  const connectionHeaders = headers.get("connection")?.split(",") ?? [];
  for (const name of [...HOP_BY_HOP_HEADERS, ...connectionHeaders]) {
    headers.delete(name.trim());
  }
}

function upstreamBaseUrl() {
  const configured =
    process.env.TALLY_API_INTERNAL_URL ?? "http://127.0.0.1:8788/api/v1/tally";
  const base = new URL(configured.endsWith("/") ? configured : `${configured}/`);
  if (base.protocol !== "http:" && base.protocol !== "https:") {
    throw new Error("TALLY_API_INTERNAL_URL must use http or https");
  }
  return base;
}

async function proxyRequest(request: Request, context: RouteContext) {
  try {
    const publicUrl = requestOrigin(request);
    const isMutation = !["GET", "HEAD", "OPTIONS"].includes(request.method);
    if (isMutation && !isSameOrigin(request, publicUrl)) {
      return NextResponse.json({ error: "Invalid request origin" }, { status: 403 });
    }
    const { path = [] } = await context.params;
    if (path.some((segment) => segment === "." || segment === "..")) {
      return NextResponse.json(
        { type: "about:blank", title: "Invalid Tally API path", status: 400 },
        { status: 400 },
      );
    }
    const target = new URL(path.map(encodeURIComponent).join("/"), upstreamBaseUrl());
    target.search = new URL(request.url).search;

    const requestHeaders = new Headers(request.headers);
    removeHopByHopHeaders(requestHeaders);
    for (const name of [
      "host",
      "content-length",
      "origin",
      "referer",
      "x-forwarded-for",
      "x-forwarded-host",
      "x-forwarded-port",
      "x-forwarded-proto",
      "x-tally-internal-token",
    ]) {
      requestHeaders.delete(name);
    }
    requestHeaders.set("accept-encoding", "identity");
    requestHeaders.set("x-forwarded-host", publicUrl.host);
    requestHeaders.set("x-forwarded-proto", publicUrl.protocol.slice(0, -1));
    if (isMutation) requestHeaders.set("origin", publicUrl.origin);

    const hasBody = request.method !== "GET" && request.method !== "HEAD";
    const body = hasBody ? await request.arrayBuffer() : undefined;
    const upstream = await fetch(target, {
      method: request.method,
      headers: requestHeaders,
      body: body && body.byteLength > 0 ? body : undefined,
      cache: "no-store",
      redirect: "manual",
      signal: request.signal,
    });

    const responseHeaders = new Headers(upstream.headers);
    removeHopByHopHeaders(responseHeaders);
    responseHeaders.delete("content-length");
    responseHeaders.delete("content-encoding");
    responseHeaders.set("cache-control", "no-store");

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    });
  } catch {
    return NextResponse.json(
      {
        type: "about:blank",
        title: "Tally API unavailable",
        status: 502,
      },
      { status: 502 },
    );
  }
}

export const GET = proxyRequest;
export const HEAD = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
export const OPTIONS = proxyRequest;
