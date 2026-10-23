/** Normalize return URLs before checking their origin: browsers strip tabs/newlines and
 * interpret backslashes as slashes in HTTP URLs. Return only the validated local path. */
export function safeReturnPath(next: string | null, origin: string): string {
  if (!next?.startsWith("/")) return "/";
  try {
    const url = new URL(next, origin);
    if (url.origin !== origin || url.pathname.startsWith("/signin")) return "/";
    // A normalized path beginning with // would become an authority when used again.
    if (url.pathname.startsWith("//")) return "/";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch { return "/"; }
}

/** A full navigation discards state from the ended session and preserves the return view. */
export function returnToSignIn() {
  const here = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  window.location.assign(new URL(`/signin?next=${encodeURIComponent(here)}`, window.location.origin).href);
}

/** For protected standalone account routes only. Public login/reset flows handle their
 * own credential errors; hosts supplying a bearer token handle their own session expiry. */
export async function authFetch(path: string, init: RequestInit = {}) {
  const response = await fetch(`/api/v1/auth/${path}`, init);
  if (response.status === 401 && typeof window !== "undefined" && !window.localStorage.getItem("auth_token")) returnToSignIn();
  return response;
}
