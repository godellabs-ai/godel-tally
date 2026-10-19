export class UpgradeApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

/** Host upgrade operations, authorized by the Tally administrator session. */
export async function upgradeApi<T>(path: string, body?: unknown): Promise<T> {
  let result: Response;
  try {
    result = await fetch(`/api/upgrade/${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      signal: AbortSignal.timeout(body === undefined ? 45_000 : 125_000),
    });
  } catch {
    throw new UpgradeApiError("The upgrade service is reconnecting. Retry in a moment.", 0);
  }
  const data = await result.json().catch(() => null);
  if (!result.ok) throw new UpgradeApiError(data?.error ?? `The upgrade service returned HTTP ${result.status}.`, result.status);
  if (data === null) throw new UpgradeApiError("The upgrade service returned an invalid response.", result.status);
  return data as T;
}

export const isTransientUpgradeError = (error: unknown) => error instanceof UpgradeApiError && [0, 502, 503, 504].includes(error.status);
