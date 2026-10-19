import { NextRequest } from "next/server";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isSameOrigin, requestOrigin } from "@/lib/request-origin";

// Upgrade execution runs on the Tally host. Only Tally
// administrators reach it, and its bearer stays on this server: browsers never hold it.
export const dynamic = "force-dynamic";
const upstream = process.env.TALLY_UPGRADE_UPSTREAM_URL ?? "http://127.0.0.1:8789";
const upstreamUrl = new URL(upstream);
if (upstreamUrl.protocol !== "http:" || upstreamUrl.origin !== upstream) {
  throw new Error("TALLY_UPGRADE_UPSTREAM_URL must be an HTTP origin");
}
const configuredOrigin = process.env.TALLY_UPGRADE_WEB_ORIGIN ?? "http://127.0.0.1:8080";
const configuredUrl = new URL(configuredOrigin);
if (!["http:", "https:"].includes(configuredUrl.protocol) || configuredUrl.origin !== configuredOrigin) {
  throw new Error("TALLY_UPGRADE_WEB_ORIGIN must be an HTTP or HTTPS origin");
}
const routes = /^(status|preview|prepare|cutover|cancel|reset|cleanup)$/;
const unavailable = "The upgrade service is unavailable on this Tally host. Restart Tally to start it.";
const noStore = { "Cache-Control": "no-store" };

let workspaceToken: string | null = null;

async function pairingCode(): Promise<string | null> {
  const stateDir = process.env.TALLY_UPGRADE_STATE_DIR;
  const code = process.env.TALLY_UPGRADE_BOOTSTRAP_CODE
    ?? (stateDir ? await readFile(join(stateDir, "pairing-code"), "utf8").catch(() => null) : null);
  return code && /^[a-f0-9]{64}$/.test(code.trim()) ? code.trim() : null;
}

/** The host service's shared workspace session. A restart issues a new pairing code. */
async function pair(): Promise<string | null> {
  const code = await pairingCode();
  if (!code) return null;
  try {
    const result = await fetch(`${upstream}/pair`, {
      method: "POST", headers: { Origin: configuredOrigin, "Content-Type": "application/json" },
      body: JSON.stringify({ code, workspace: true }), cache: "no-store",
      redirect: "error", signal: AbortSignal.timeout(10_000),
    });
    const body = result.ok ? await result.json() as { token?: string } : null;
    workspaceToken = body?.token && /^[a-f0-9]{64}$/.test(body.token) ? body.token : null;
  } catch { workspaceToken = null; }
  return workspaceToken;
}

async function isAdministrator(request: NextRequest): Promise<boolean | null> {
  const cookie = request.headers.get("cookie");
  if (!cookie) return false;
  try {
    const base = process.env.TALLY_AUTH_INTERNAL_URL ?? "http://127.0.0.1:8788/api/v1/auth";
    const auth = await fetch(`${base}/me`, { headers: { cookie }, cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (auth.status === 401 || auth.status === 403) return false;
    if (!auth.ok) return null;
    const body = await auth.json() as { user?: { role?: string } };
    return body.user?.role === "admin";
  } catch { return null; }
}

async function proxy(request: NextRequest, context: { params: Promise<{ path?: string[] }> }) {
  const path = (await context.params).path?.join("/") ?? "";
  const publicUrl = requestOrigin(request);
  const mutation = !["GET", "HEAD", "OPTIONS"].includes(request.method);
  if ((mutation && !isSameOrigin(request, publicUrl)) || request.headers.get("sec-fetch-site") === "cross-site") {
    return Response.json({ error: "Upgrade accepts requests only from the same Tally console origin." }, { status: 403, headers: noStore });
  }
  const admin = await isAdministrator(request);
  if (admin === null) return Response.json({ error: "Tally authentication unavailable." }, { status: 503, headers: noStore });
  if (!admin) return Response.json({ error: "Tally administrator access required." }, { status: 403, headers: noStore });
  if (path === "health") {
    const ready = Boolean(workspaceToken ?? await pair());
    return Response.json({ ready }, { headers: noStore });
  }
  if (!routes.test(path)) return Response.json({ error: "Unknown Upgrade route." }, { status: 404, headers: noStore });
  const targetPath = path === "status" ? "upgrade" : `upgrade/${path}`;
  let body: Uint8Array | undefined;
  if (mutation && request.body) {
    const reader = request.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
    while (true) {
      const { value, done } = await reader.read(); if (done) break;
      size += value.length;
      if (size > 1_000_000) { await reader.cancel(); return Response.json({ error: "Request is too large." }, { status: 413, headers: noStore }); }
      chunks.push(value);
    }
    body = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  }
  const forward = (token: string) => fetch(`${upstream}/${targetPath}`, {
    method: request.method, body: body as BodyInit | undefined, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(115_000),
    // The public request has passed CSRF and role checks; the host service keeps its private origin.
    headers: { Origin: configuredOrigin, Authorization: `Bearer ${token}`, ...(body ? { "Content-Type": request.headers.get("content-type") ?? "application/json" } : {}) },
  });
  try {
    let token = workspaceToken ?? await pair();
    if (!token) return Response.json({ error: unavailable }, { status: 503, headers: noStore });
    let result = await forward(token);
    // A rejected bearer means the service restarted; the request did not run, so retry once.
    if (result.status === 401 && (token = await pair())) result = await forward(token);
    return new Response(result.body, { status: result.status, headers: { "Content-Type": result.headers.get("content-type") ?? "application/json", ...noStore } });
  } catch {
    workspaceToken = null;
    return Response.json({ error: unavailable }, { status: 503, headers: noStore });
  }
}
export { proxy as GET, proxy as POST };
