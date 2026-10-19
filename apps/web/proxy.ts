import { NextRequest, NextResponse } from "next/server";
import { requestOrigin } from "@/lib/request-origin";

export async function proxy(request: NextRequest) {
  const path = request.nextUrl.pathname;
  if (path === "/signin" || path === "/forgot-password" || path === "/reset-password") return NextResponse.next();
  const cookie = request.headers.get("cookie");
  if (!cookie?.includes("tally_session=")) return unauthenticated(request);
  try {
    const base = process.env.TALLY_AUTH_INTERNAL_URL ?? "http://127.0.0.1:8788/api/v1/auth";
    const response = await fetch(`${base}/me`, { headers: { cookie }, cache: "no-store", signal: AbortSignal.timeout(5000) });
    if (response.ok) return NextResponse.next();
    if (response.status === 401 || response.status === 403) return unauthenticated(request);
  } catch { /* Keep access blocked while Tally cannot verify the session. */ }
  // A temporary API outage is not an expired login. The upgrade page must
  // keep entered upgrade details while make dev rebuilds Tally.
  return NextResponse.json({ error: "Tally is temporarily unavailable. Please try again shortly." }, {
    status: 503,
    headers: { "Cache-Control": "no-store", "Retry-After": "5" },
  });
}

function unauthenticated(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }
  return NextResponse.redirect(new URL("/signin", requestOrigin(request)));
}

export const config = {
  matcher: ["/((?!api/v1/auth|api/v1/tally/health|_next|favicon|.*\\.(?:svg|png|ico|jpg|webp|woff2)$).*)"],
};
