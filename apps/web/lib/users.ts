export type User = { id: string; email: string; display_name: string; first_name: string | null; last_name: string | null; role: "admin" | "member"; disabled: boolean; has_password: boolean };

export class UsersApiError extends Error {
  status: number;
  constructor(message: string, status: number) { super(message); this.status = status; }
}

export const isTransientUsersError = (cause: unknown) => cause instanceof UsersApiError && [0, 502, 503, 504].includes(cause.status);

async function read<T>(path: string, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api/v1/auth/${path}`, { cache: "no-store", signal: AbortSignal.any([
      AbortSignal.timeout(10_000), ...(signal ? [signal] : []),
    ]) });
  } catch {
    if (signal?.aborted) throw signal.reason;
    throw new UsersApiError("Tally is reconnecting. Retrying automatically.", 0);
  }
  if (!response.ok) {
    const message = response.status === 401 ? "Sign in to view console users."
      : response.status === 403 ? "Administrator access is required."
      : [502, 503, 504].includes(response.status) ? "Tally is reconnecting. Retrying automatically."
      : "Could not load console users. Please retry.";
    throw new UsersApiError(message, response.status);
  }
  try { return await response.json() as T; }
  catch { throw new UsersApiError("Could not read the console users response. Please retry.", response.status); }
}

export async function loadUsers(signal?: AbortSignal) {
  const [people, me] = await Promise.all([
    read<{ users: User[] }>("users", signal), read<{ user: { id: string } }>("me", signal),
  ]);
  return { users: people.users, currentUserId: me.user.id };
}
