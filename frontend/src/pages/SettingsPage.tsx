import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../store/auth";
import { Button, Card, Spinner } from "../components/ui";

export default function SettingsPage() {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    api.get<Record<string, unknown>>("/system/info").then(setInfo).catch(() => {});
  }, []);

  async function changePassword() {
    setMessage(null);
    try {
      await api.post("/auth/change-password", { current_password: current, new_password: next });
      setMessage("Password changed.");
      setCurrent("");
      setNext("");
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "failed");
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Settings</h1>
        <p className="text-sm text-sentinel-muted">Session, credentials and local platform configuration.</p>
      </header>

      <Card title="Session" subtitle="Authenticated via local JWT">
        <dl className="space-y-1 text-sm">
          <div className="flex justify-between"><dt className="text-sentinel-muted">User</dt><dd className="text-slate-200">{user?.username}</dd></div>
          <div className="flex justify-between"><dt className="text-sentinel-muted">Display name</dt><dd className="text-slate-200">{user?.display_name}</dd></div>
          <div className="flex justify-between"><dt className="text-sentinel-muted">Role</dt><dd className="text-cyan-300">{user?.role}</dd></div>
        </dl>
        <div className="mt-3">
          <Button variant="ghost" onClick={logout}>Sign out</Button>
        </div>
      </Card>

      <Card title="Change password" subtitle="Minimum 10 chars, letter + digit">
        <div className="grid gap-3 sm:grid-cols-2">
          <input type="password" placeholder="current password" value={current} onChange={(e) => setCurrent(e.target.value)} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
          <input type="password" placeholder="new password" value={next} onChange={(e) => setNext(e.target.value)} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
        </div>
        <div className="mt-3 flex items-center gap-3">
          <Button onClick={changePassword} disabled={!current || !next}>Update password</Button>
          {message && <span className="text-sm text-sentinel-muted">{message}</span>}
        </div>
      </Card>

      <Card title="Platform" subtitle="Local runtime facts (ADR-001: modular monolith)">
        {info ? (
          <pre className="overflow-x-auto text-xs text-slate-400">{JSON.stringify(info, null, 2)}</pre>
        ) : (
          <Spinner />
        )}
        <p className="mt-3 text-xs text-sentinel-muted">
          Configuration uses <code>SENTINEL_*</code> environment variables — see{" "}
          <code>backend/.env.example</code>. No secrets are stored in the browser or in source.
        </p>
      </Card>
    </div>
  );
}