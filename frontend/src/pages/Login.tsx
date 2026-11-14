import { useState } from "react";
import { Button } from "../components/ui";
import { useAuth } from "../store/auth";

export default function Login() {
  const login = useAuth((s) => s.login);
  const verifyMfa = useAuth((s) => s.verifyMfa);
  const clearMfa = useAuth((s) => s.clearMfa);
  const error = useAuth((s) => s.error);
  const mfaToken = useAuth((s) => s.mfaToken);
  const loading = useAuth((s) => s.loading);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);

  async function submitMfa() {
    if (useRecovery) {
      await verifyMfa("", recoveryCode.trim());
      setRecoveryCode("");
      return;
    }
    await verifyMfa(code.trim());
    setCode("");
  }

  if (mfaToken) {
    return (
      <div className="flex h-full items-center justify-center bg-gradient-to-br from-[#0b1220] via-[#0e1626] to-[#0b1220]">
        <div className="w-full max-w-sm rounded-2xl border border-sentinel-border bg-sentinel-surface/90 p-8 shadow-2xl shadow-cyan-900/20">
          <div className="mb-6 text-center">
            <div className="text-2xl font-bold tracking-wide text-cyan-300">SENTINEL-M</div>
            <div className="text-xs uppercase tracking-[0.3em] text-sentinel-muted">
              Two-factor verification
            </div>
          </div>
          {error && (
            <p className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              {error}
            </p>
          )}
          {useRecovery ? (
            <div className="space-y-4">
              <input
                autoFocus
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submitMfa()}
                placeholder="recovery code"
                className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              />
              <div className="flex gap-2">
                <Button variant="primary" onClick={submitMfa} disabled={!recoveryCode.trim() || loading}>
                  Use recovery code
                </Button>
                <Button variant="ghost" onClick={() => setUseRecovery(false)}>Back to authenticator</Button>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <input
                autoFocus
                inputMode="numeric"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && submitMfa()}
                placeholder="6-digit authenticator code"
                className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              />
              <div className="flex gap-2">
                <Button variant="primary" onClick={submitMfa} disabled={code.trim().length < 6 || loading}>Verify</Button>
                <Button variant="ghost" onClick={() => setUseRecovery(true)}>Use a recovery code</Button>
              </div>
            </div>
          )}
          <div className="mt-4 text-center">
            <button onClick={clearMfa} className="text-xs text-slate-400 underline hover:text-red-300">
              cancel and sign in again
            </button>
          </div>
        </div>
      </div>
    );
  }

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