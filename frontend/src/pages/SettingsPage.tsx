import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { useAuth } from "../store/auth";
import { Badge, Button, Card, Spinner } from "../components/ui";

interface MfaStatus {
  enabled: boolean;
  pending_enrollment: boolean;
  enrolled_at: string | null;
  recovery_codes_remaining: number;
}

interface MfaEnrollment {
  secret: string;
  provisioning_uri: string;
  recovery_codes: string[];
  digits: number;
  period: number;
}

export default function SettingsPage() {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [mfaStatus, setMfaStatus] = useState<MfaStatus | null>(null);
  const [mfaEnrollment, setMfaEnrollment] = useState<MfaEnrollment | null>(null);
  const [mfaLoading, setMfaLoading] = useState(false);
  const [mfaError, setMfaError] = useState<string | null>(null);
  const [activateCode, setActivateCode] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");

  const loadMfaStatus = useCallback(() => {
    api.get<MfaStatus>("/auth/mfa/status").then(setMfaStatus).catch(() => {});
  }, []);

  useEffect(() => {
    api.get<Record<string, unknown>>("/system/info").then(setInfo).catch(() => {});
    loadMfaStatus();
  }, [loadMfaStatus]);

  async function startMfaSetup() {
    setMfaLoading(true);
    setMfaError(null);
    try {
      const res = await api.post<MfaEnrollment>("/auth/mfa/setup");
      setMfaEnrollment(res);
      loadMfaStatus();
    } catch (e) {
      setMfaError(e instanceof Error ? e.message : "setup failed");
    } finally {
      setMfaLoading(false);
    }
  }

  async function activateMfa() {
    setMfaLoading(true);
    setMfaError(null);
    try {
      await api.post("/auth/mfa/activate", { code: activateCode.trim() });
      setMfaEnrollment(null);
      setActivateCode("");
      loadMfaStatus();
    } catch (e) {
      setMfaError(e instanceof Error ? e.message : "activation failed");
    } finally {
      setMfaLoading(false);
    }
  }

  async function disableMfa() {
    setMfaLoading(true);
    setMfaError(null);
    try {
      await api.post("/auth/mfa/disable", { password: disablePassword, code: disableCode.trim() });
      setDisablePassword("");
      setDisableCode("");
      loadMfaStatus();
    } catch (e) {
      setMfaError(e instanceof Error ? e.message : "disable failed");
    } finally {
      setMfaLoading(false);
    }
  }

  const mfa = {
    status: mfaStatus,
    enrollment: mfaEnrollment,
    loading: mfaLoading,
    error: mfaError,
    startSetup: startMfaSetup,
    activate: activateMfa,
    disable: disableMfa,
    cancelEnrollment: () => { setMfaEnrollment(null); setActivateCode(""); },
    activateCode,
    disablePassword,
    disableCode,
  };

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

      <Card title="Two-factor authentication (TOTP)" subtitle="RFC 6238 — authenticator app, no external service">
        {mfa.loading && !mfa.status ? (
          <Spinner />
        ) : (
          <div className="space-y-3 text-sm">
            <div className="flex items-center gap-3">
              <Badge className={mfa.status?.enabled
                ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                : "border-slate-500/40 bg-slate-500/15 text-slate-300"}>
                {mfa.status?.enabled ? "enabled" : mfa.status?.pending_enrollment ? "pending enrollment" : "disabled"}
              </Badge>
              {mfa.status?.recovery_codes_remaining !== undefined && mfa.status.enabled && (
                <span className="text-xs text-sentinel-muted">
                  {mfa.status.recovery_codes_remaining} recovery codes left
                </span>
              )}
            </div>

            {mfa.error && (
              <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{mfa.error}</p>
            )}

            {!mfa.status?.enabled && !mfa.enrollment && (
              <Button onClick={mfa.startSetup} disabled={mfa.loading}>Set up authenticator app</Button>
            )}

            {mfa.enrollment && (
              <div className="space-y-3 rounded-lg border border-sentinel-border bg-sentinel-bg/60 p-3">
                <p className="text-xs text-sentinel-muted">
                  1. Add this secret to your authenticator app (or scan the provisioning URI).
                </p>
                <pre className="select-all rounded bg-sentinel-bg p-2 text-xs text-cyan-300">{mfa.enrollment.secret}</pre>
                <p className="break-all text-[10px] text-slate-500">{mfa.enrollment.provisioning_uri}</p>
                <p className="text-xs font-semibold text-red-300">
                  2. Save these recovery codes now — shown once:
                </p>
                <pre className="select-all rounded bg-sentinel-bg p-2 text-xs text-amber-200">
                  {mfa.enrollment.recovery_codes.join("\n")}
                </pre>
                <p className="text-xs text-sentinel-muted">3. Enter the current 6-digit code to activate:</p>
                <div className="flex gap-2">
                  <input
                    inputMode="numeric"
                    value={mfa.activateCode}
                    onChange={(e) => setActivateCode(e.target.value)}
                    placeholder="6-digit code"
                    className="w-40 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm"
                  />
                  <Button variant="primary" onClick={mfa.activate} disabled={mfa.activateCode.length < 6 || mfa.loading}>
                    Activate MFA
                  </Button>
                  <Button variant="ghost" onClick={mfa.cancelEnrollment}>Cancel</Button>
                </div>
              </div>
            )}

            {mfa.status?.enabled && (
              <div className="space-y-2 rounded-lg border border-sentinel-border bg-sentinel-bg/60 p-3">
                <p className="text-xs text-sentinel-muted">Disable MFA — requires your password AND a live code.</p>
                <div className="flex flex-wrap gap-2">
                  <input
                    type="password"
                    value={mfa.disablePassword}
                    onChange={(e) => setDisablePassword(e.target.value)}
                    placeholder="current password"
                    className="w-44 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm"
                  />
                  <input
                    inputMode="numeric"
                    value={mfa.disableCode}
                    onChange={(e) => setDisableCode(e.target.value)}
                    placeholder="6-digit code"
                    className="w-32 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm"
                  />
                  <Button variant="danger" onClick={mfa.disable} disabled={!mfa.disablePassword || mfa.disableCode.length < 6 || mfa.loading}>
                    Disable MFA
                  </Button>
                </div>
              </div>
            )}
          </div>
        )}
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