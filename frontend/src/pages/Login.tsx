import { useState } from "react";
import { useAuth } from "../store/auth";

export default function Login() {
  const login = useAuth((s) => s.login);
  const error = useAuth((s) => s.error);
  const loading = useAuth((s) => s.loading);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  return (
    <div className="flex h-full items-center justify-center bg-gradient-to-br from-[#0b1220] via-[#0e1626] to-[#0b1220]">
      <div className="w-full max-w-sm rounded-2xl border border-sentinel-border bg-sentinel-surface/90 p-8 shadow-2xl shadow-cyan-900/20">
        <div className="mb-6 text-center">
          <div className="text-2xl font-bold tracking-wide text-cyan-300">SENTINEL-M</div>
          <div className="text-xs uppercase tracking-[0.3em] text-sentinel-muted">
            Autonomous Cyber Defense
          </div>
        </div>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            await login(username, password);
          }}
          className="space-y-4"
        >
          <label className="block">
            <span className="text-xs font-medium text-sentinel-muted">Username</span>
            <input
              autoFocus
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              placeholder="admin"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-sentinel-muted">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              placeholder="••••••••••"
            />
          </label>
          {error && (
            <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={loading || !username || !password}
            className="w-full rounded-lg border border-cyan-500/50 bg-cyan-600 py-2 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Authenticating…" : "Sign in"}
          </button>
        </form>
        <p className="mt-6 text-center text-[11px] leading-relaxed text-sentinel-muted">
          Local-first platform · JWT session · All sign-in activity is audit-logged
        </p>
      </div>
    </div>
  );
}