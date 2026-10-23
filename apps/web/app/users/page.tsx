"use client";

import { useCallback, useEffect, useState } from "react";
import { isTransientUsersError, loadInvitations, loadUsers, type Invitation, type User } from "@/lib/users";
import { formatDateTime } from "@/lib/datetime";
import { authFetch } from "@/lib/session";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [currentUserId, setCurrentUserId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [nameError, setNameError] = useState("");
  const [changingPassword, setChangingPassword] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const [email, setEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"member" | "admin">("member");
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [inviteUrl, setInviteUrl] = useState("");
  const [resetLink, setResetLink] = useState<{ userId: string; url: string; expiresAt: string } | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadAttempt, setLoadAttempt] = useState(0);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const [result, pending] = await Promise.all([loadUsers(signal), loadInvitations(signal)]);
      if (signal?.aborted) return;
      setUsers(result.users); setCurrentUserId(result.currentUserId); setInvitations(pending);
      setLoading(false); setError("");
    } catch (cause) {
      if (!signal?.aborted) {
        setLoading(false);
        setError(cause instanceof Error ? cause.message : "Could not load console users.");
      }
      throw cause;
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>, pending = false, retrying = true;
    const refresh = async () => {
      if (pending || !retrying || controller.signal.aborted) return;
      clearTimeout(timer); pending = true; setLoading(true);
      try { await load(controller.signal); retrying = false; }
      catch (cause) {
        retrying = isTransientUsersError(cause);
        if (retrying && !controller.signal.aborted) timer = setTimeout(() => { void refresh(); }, 5000);
      } finally { pending = false; }
    };
    const awake = () => { if (document.visibilityState === "visible") void refresh(); };
    timer = setTimeout(() => { void refresh(); }, 0);
    window.addEventListener("online", awake); window.addEventListener("focus", awake); document.addEventListener("visibilitychange", awake);
    return () => {
      controller.abort(); clearTimeout(timer);
      window.removeEventListener("online", awake); window.removeEventListener("focus", awake); document.removeEventListener("visibilitychange", awake);
    };
  }, [load, loadAttempt]);

  async function request(path: string, body: unknown, method: "POST" | "DELETE" = "POST") {
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await authFetch(path, method === "DELETE" ? { method } : { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error((await response.json()).error || "Request failed");
      return response;
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Request failed"); throw cause; }
    finally { setBusy(false); }
  }

  async function createInvite(event: React.FormEvent) {
    event.preventDefault();
    try {
      const response = await request("invitations", { email, role: inviteRole });
      setInviteUrl((await response.json()).invite_url);
      setEmail(""); setInviteRole("member");
      setNotice("Invitation created. Copy this link now; it is shown only once. Any earlier link for this address no longer works.");
      await load();
    } catch { /* request shows the error */ }
  }

  async function revoke(invitation: Invitation) {
    try {
      await request(`invitations/${encodeURIComponent(invitation.id)}`, null, "DELETE");
      setNotice(`Invitation for ${invitation.email} revoked. Its link no longer works.`);
      await load();
    } catch { /* request shows the error */ }
  }

  async function changeRole(user: User) {
    const role = user.role === "admin" ? "member" : "admin";
    try {
      await request(`users/${encodeURIComponent(user.id)}/role`, { role });
      setNotice(role === "admin" ? `${user.display_name} is now an administrator.` : `${user.display_name} is now a member.`);
      await load();
    } catch { /* request shows the error */ }
  }

  async function toggle(user: User) {
    try {
      await request(`users/${encodeURIComponent(user.id)}`, { disabled: !user.disabled });
      await load();
    } catch { /* request shows the error */ }
  }

  function editName(user: User) {
    setError(""); setNameError(""); setEditingId(user.id); setChangingPassword(false);
    setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
    setFirstName(user.first_name ?? ""); setLastName(user.last_name ?? "");
  }

  async function saveName(event: React.FormEvent) {
    event.preventDefault();
    if (!editingId) return;
    setNameError("");
    try {
      await request(`users/${encodeURIComponent(editingId)}/name`, { first_name: firstName.trim(), last_name: lastName.trim() });
      setEditingId(null); setNotice("Name updated."); await load();
    } catch (cause) { setNameError(cause instanceof Error ? cause.message : "Could not update name."); }
  }

  async function savePassword(event: React.FormEvent) {
    event.preventDefault();
    setPasswordError("");
    if (newPassword !== confirmPassword) { setPasswordError("New passwords do not match."); return; }
    try {
      await request("me/password", { current_password: currentPassword, new_password: newPassword });
      setCurrentPassword(""); setNewPassword(""); setConfirmPassword("");
      setChangingPassword(false); setNotice("Password changed. Other sessions were signed out.");
    } catch (cause) { setPasswordError(cause instanceof Error ? cause.message : "Could not change password."); }
  }

  async function resetPassword(user: User) {
    setResetLink(null);
    try {
      const response = await request(`users/${encodeURIComponent(user.id)}/password-reset`, {});
      const result = await response.json() as { reset_url: string; expires_at: string; emailed: boolean };
      setResetLink({ userId: user.id, url: result.reset_url, expiresAt: result.expires_at });
      setNotice(result.emailed ? `A one-time reset link was emailed to ${user.email}. You can also copy it below.`
        : "Copy the one-time reset link and share it securely. It is shown only here.");
    } catch { /* request shows the error */ }
  }

  const field = "mt-1 w-full rounded-md border border-border bg-background p-2 text-sm";
  return <div className="space-y-8">
    <div><h2 className="text-xl font-bold">Console users</h2><p className="text-sm text-muted-foreground">The first user is an administrator. Other people join through an invitation, as a member or an administrator. Tally always keeps at least one enabled administrator.</p></div>
    {error && <div role="alert" className="flex items-center justify-between gap-3 rounded-md bg-destructive/10 p-3 text-sm text-destructive"><span>{error}</span><button type="button" disabled={loading} onClick={() => setLoadAttempt(attempt => attempt + 1)} className="shrink-0 rounded-md border px-3 py-1 disabled:opacity-50">Retry</button></div>}
    {notice && <p role="status" className="rounded-md bg-primary/10 p-3 text-sm">{notice}</p>}
    <section className="rounded-xl border border-border bg-card p-5"><h3 className="font-semibold">Invite a user</h3>
      <form onSubmit={createInvite} className="mt-4 flex flex-wrap items-end gap-3">
        <label className="min-w-0 basis-64 flex-1 text-xs font-semibold">Email address<input required type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="person@example.com" className={field} /></label>
        <label className="text-xs font-semibold">Role<select value={inviteRole} onChange={e => setInviteRole(e.target.value === "admin" ? "admin" : "member")} className={field}><option value="member">Member</option><option value="admin">Administrator</option></select></label>
        <button disabled={busy} className="rounded-md bg-primary px-4 py-2 text-primary-foreground">Create invitation</button>
      </form>
      <p className="mt-2 text-xs text-muted-foreground">Members review the estate and record decisions. Administrators also manage users, connectors, settings and data removal.</p>
      {inviteUrl && <div className="mt-4"><label className="text-xs font-semibold">One-time invitation link<input readOnly value={inviteUrl} onFocus={e => e.target.select()} className={field} /></label></div>}
    </section>
    {invitations.length > 0 && <section className="rounded-xl border border-border bg-card p-5"><h3 className="font-semibold">Pending invitations</h3>
      <div className="mt-4 divide-y divide-border">{invitations.map(invitation => <div key={invitation.id} className="flex flex-wrap items-center justify-between gap-3 break-words [overflow-wrap:anywhere] py-3 text-sm">
        <div className="min-w-0 max-w-full"><strong className="break-all">{invitation.email}</strong><div className="break-words text-muted-foreground">{invitation.role === "admin" ? "Administrator" : "Member"} · expires {formatDateTime(invitation.expires_at)}{invitation.invited_by ? ` · invited by ${invitation.invited_by}` : ""}</div></div>
        <button type="button" disabled={busy} onClick={() => void revoke(invitation)} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50" aria-label={`Revoke invitation for ${invitation.email}`}>Revoke</button>
      </div>)}</div>
    </section>}
    <section className="rounded-xl border border-border bg-card p-5"><h3 className="font-semibold">People with access</h3>
      {loading && <p role="status" className="mt-4 text-sm text-muted-foreground">Loading console users…</p>}
      <div className="mt-4 divide-y divide-border">{users.map(user => <div key={user.id} className="break-words [overflow-wrap:anywhere] py-3 text-sm">
        <div className="flex flex-wrap items-center justify-between gap-3"><div className="min-w-0 max-w-full"><strong>{user.display_name}</strong><div className="break-all text-muted-foreground">{user.email} · {user.role}{user.disabled ? " · disabled" : ""}{user.has_password ? "" : " · no password set"}</div></div>
          <div className="flex flex-wrap gap-2"><button type="button" disabled={busy} onClick={() => editName(user)} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50">Edit name</button>
            {user.id === currentUserId && user.has_password && <button type="button" disabled={busy} onClick={() => { setError(""); setPasswordError(""); setEditingId(null); setCurrentPassword(""); setNewPassword(""); setConfirmPassword(""); setChangingPassword(true); }} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50">Change password</button>}
            {user.id !== currentUserId && !user.disabled && <button type="button" disabled={busy} onClick={() => void resetPassword(user)} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50">{user.has_password ? "Reset password" : "Send password link"}</button>}
            {user.id !== currentUserId && !user.disabled && <button type="button" disabled={busy} onClick={() => void changeRole(user)} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50">{user.role === "admin" ? "Make member" : "Make administrator"}</button>}
            <button type="button" disabled={busy || user.id === currentUserId} onClick={() => toggle(user)} className="rounded-md border border-border px-3 py-1.5 disabled:opacity-50">{user.disabled ? "Enable" : "Disable"}</button></div></div>
        {resetLink?.userId === user.id && <div className="mt-3 rounded-lg border border-primary/30 bg-primary/5 p-3"><label className="text-xs font-semibold">One-time password reset link<input readOnly value={resetLink.url} onFocus={event => event.target.select()} className={field} /></label><p className="mt-1 text-xs text-muted-foreground">Expires {formatDateTime(resetLink.expiresAt)}. The user sets their own password.</p></div>}
        {editingId === user.id && <form onSubmit={saveName} className="mt-3 grid gap-3 rounded-lg border border-border bg-background/50 p-3 sm:grid-cols-2">
          <label className="text-xs font-semibold">First name<input required maxLength={100} autoComplete="given-name" value={firstName} onChange={event => setFirstName(event.target.value)} className={field} /></label>
          <label className="text-xs font-semibold">Last name<input required maxLength={100} autoComplete="family-name" value={lastName} onChange={event => setLastName(event.target.value)} className={field} /></label>
          {nameError && <p role="alert" className="text-xs text-destructive sm:col-span-2">{nameError}</p>}
          <div className="flex gap-2 sm:col-span-2"><button disabled={busy} className="rounded-md bg-primary px-3 py-1.5 font-semibold text-primary-foreground disabled:opacity-50">Save name</button><button type="button" disabled={busy} onClick={() => setEditingId(null)} className="rounded-md border border-border px-3 py-1.5">Cancel</button></div>
        </form>}
        {user.id === currentUserId && changingPassword && <form onSubmit={savePassword} className="mt-3 grid gap-3 rounded-lg border border-border bg-background/50 p-3 sm:grid-cols-3">
          <label className="text-xs font-semibold">Current password<input required type="password" autoComplete="current-password" value={currentPassword} onChange={event => setCurrentPassword(event.target.value)} className={field} /></label>
          <label className="text-xs font-semibold">New password<input required type="password" minLength={12} autoComplete="new-password" value={newPassword} onChange={event => setNewPassword(event.target.value)} className={field} /></label>
          <label className="text-xs font-semibold">Confirm new password<input required type="password" minLength={12} autoComplete="new-password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} className={field} /></label>
          {passwordError && <p role="alert" className="text-xs text-destructive sm:col-span-3">{passwordError}</p>}
          <div className="flex gap-2 sm:col-span-3"><button disabled={busy} className="rounded-md bg-primary px-3 py-1.5 font-semibold text-primary-foreground disabled:opacity-50">Save password</button><button type="button" disabled={busy} onClick={() => { setChangingPassword(false); setCurrentPassword(""); setNewPassword(""); setConfirmPassword(""); }} className="rounded-md border border-border px-3 py-1.5">Cancel</button></div>
        </form>}
      </div>)}</div>
    </section>
  </div>;
}
