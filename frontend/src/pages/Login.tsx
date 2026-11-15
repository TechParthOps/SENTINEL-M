import { useEffect, useState } from "react";
import { Button } from "../components/ui";
import { useAuth } from "../store/auth";

export default function Login() {
  const login = useAuth((s) => s.login);
  const verifyMfa = useAuth((s) => s.verifyMfa);
  const clearMfa = useAuth((s) => s.clearMfa);
  const register = useAuth((s) => s.register);
  const checkBootstrap = useAuth((s) => s.checkBootstrap);
  const needsSetup = useAuth((s) => s.needsSetup);
  const error = useAuth((s) => s.error);
  const mfaToken = useAuth((s) => s.mfaToken);
  const loading = useAuth((s) => s.loading);
  const user = useAuth((s) => s.user);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  // regular visitors get BOTH options: sign in, or create their own account
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [suUser, setSuUser] = useState("");
  const [suDisplay, setSuDisplay] = useState("");
  const [suPass, setSuPass] = useState("");
  const [suConfirm, setSuConfirm] = useState("");
  const [suRole, setSuRole] = useState<"analyst" | "viewer">("viewer");
  const allowSelfRegistration = useAuth((s) => s.allowSelfRegistration);

  // first launch only: offer account creation when no users exist yet
  useEffect(() => {
    if (needsSetup === null) void checkBootstrap();
  }, [needsSetup, checkBootstrap]);

  // a signed-in user on /login (register, MFA verify, direct URL) goes to the app
  useEffect(() => {
    if (user) location.assign("/overview");
  }, [user]);

  if (needsSetup) {
    return (
      <FirstLaunchSetup
        loading={loading}
        error={error}
        register={register}
      />
    );
  }

  if (mode === "signup") {
    return (
      <SignupScreen
        loading={loading}
        error={error}
        disabled={!allowSelfRegistration}
        username={suUser}
        setUsername={setSuUser}
        displayName={suDisplay}
        setDisplayName={setSuDisplay}
        password={suPass}
        setPassword={setSuPass}
        confirm={suConfirm}
        setConfirm={setSuConfirm}
        role={suRole}
        setRole={setSuRole}
        onCancel={() => setMode("signin")}
        onSubmit={async () => {
          const ok = await register({
            username: suUser.trim(),
            display_name: suDisplay.trim() || suUser.trim(),
            password: suPass,
            role: suRole,
          });
          if (ok) {
            setSuUser(""); setSuDisplay(""); setSuPass(""); setSuConfirm("");
          }
        }}
      />
    );
  }

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
              placeholder="username"
            />
          </label>
          <label className="block">
            <span className="text-xs font-medium text-sentinel-muted">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
              placeholder="**********"
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
        {allowSelfRegistration ? (
          <p className="mt-3 text-center text-xs text-slate-400">
            No account yet?{" "}
            <button onClick={() => setMode("signup")} className="text-cyan-300 underline hover:text-cyan-200">
              Create one
            </button>
          </p>
        ) : (
          <p className="mt-3 text-center text-xs text-slate-500">
            Account creation is disabled on this instance — ask an administrator.
          </p>
        )}
      </div>
    </div>
  );
}

/** Regular self-registration (non-admin roles only; admin requires an existing admin). */
function SignupScreen(props: {
  loading: boolean;
  error: string | null;
  disabled: boolean;
  username: string;
  setUsername: (v: string) => void;
  displayName: string;
  setDisplayName: (v: string) => void;
  password: string;
  setPassword: (v: string) => void;
  confirm: string;
  setConfirm: (v: string) => void;
  role: "analyst" | "viewer";
  setRole: (v: "analyst" | "viewer") => void;
  onCancel: () => void;
  onSubmit: () => Promise<void>;
}) {
  const {
    loading, error, disabled, username, setUsername, displayName, setDisplayName,
    password, setPassword, confirm, setConfirm, role, setRole, onCancel, onSubmit,
  } = props;
  const [localError, setLocalError] = useState<string | null>(null);
  const valid = username.trim().length >= 3 && password.length >= 10
    && /[a-zA-Z]/.test(password) && /\d/.test(password) && password === confirm;
  const shown = localError ?? error;

  return (
    <div className="flex h-full items-center justify-center bg-gradient-to-br from-[#0b1220] via-[#0e1626] to-[#0b1220]">
      <div className="w-full max-w-sm rounded-2xl border border-sentinel-border bg-sentinel-surface/90 p-8 shadow-2xl shadow-cyan-900/20">
        <div className="mb-6 text-center">
          <div className="text-2xl font-bold tracking-wide text-cyan-300">SENTINEL-M</div>
          <div className="text-xs uppercase tracking-[0.3em] text-sentinel-muted">
            Create your account
          </div>
        </div>
        {disabled && (
          <p className="mb-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-200">
            Self-registration is disabled on this instance. An administrator must create your account.
          </p>
        )}
        {shown && !disabled && (
          <p className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">{shown}</p>
        )}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setLocalError(null);
            if (!valid) {
              setLocalError(password !== confirm
                ? "Passwords do not match"
                : "Username >= 3 chars; password >= 10 chars with a letter and a digit");
              return;
            }
            await onSubmit();
          }}
          className="space-y-3"
        >
          <input
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="username"
            disabled={disabled}
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60 disabled:opacity-50"
          />
          <input
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="display name (optional)"
            disabled={disabled}
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60 disabled:opacity-50"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password (10+ chars, letter + digit)"
            disabled={disabled}
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60 disabled:opacity-50"
          />
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="confirm password"
            disabled={disabled}
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60 disabled:opacity-50"
          />
          <div className="grid grid-cols-2 gap-2 pt-1">
            {([
              ["viewer", "Normal user", "read-only dashboards and investigations"],
              ["analyst", "Analyst", "triage alerts, run hunts and investigations"],
            ] as const).map(([value, label, hint]) => (
              <button
                key={value}
                type="button"
                onClick={() => setRole(value)}
                className={`rounded-lg border p-2 text-left text-xs transition-colors ${
                  role === value
                    ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-100"
                    : "border-sentinel-border text-slate-300 hover:bg-white/5"
                }`}
              >
                <div className="text-sm font-semibold">{label}</div>
                <div className="mt-0.5 text-[10px] text-sentinel-muted">{hint}</div>
              </button>
            ))}
          </div>
          <button
            type="submit"
            disabled={loading || disabled}
            className="w-full rounded-lg border border-cyan-500/50 bg-cyan-600 py-2 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Creating account..." : "Create account and sign in"}
          </button>
          <button type="button" onClick={onCancel} className="w-full text-xs text-slate-400 underline hover:text-red-300">
            back to sign in
          </button>
        </form>
        <p className="mt-4 text-center text-[11px] text-sentinel-muted">
          Administrator accounts are created by an existing administrator (or at first launch).
        </p>
      </div>
    </div>
  );
}

/** First launch only - no accounts exist yet, so no password is ever printed. */
function FirstLaunchSetup({ loading, error, register }: {
  loading: boolean;
  error: string | null;
  register: (account: {
    username: string;
    display_name: string;
    password: string;
    role: "admin" | "viewer";
  }) => Promise<boolean>;
}) {
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [role, setRole] = useState<"admin" | "viewer">("admin");
  const [localError, setLocalError] = useState<string | null>(null);

  const shown = localError ?? error;
  const valid =
    username.trim().length >= 3 &&
    password.length >= 10 &&
    /[a-zA-Z]/.test(password) &&
    /\d/.test(password) &&
    password === confirm;

  return (
    <div className="flex h-full items-center justify-center bg-gradient-to-br from-[#0b1220] via-[#0e1626] to-[#0b1220]">
      <div className="w-full max-w-sm rounded-2xl border border-sentinel-border bg-sentinel-surface/90 p-8 shadow-2xl shadow-cyan-900/20">
        <div className="mb-6 text-center">
          <div className="text-2xl font-bold tracking-wide text-cyan-300">SENTINEL-M</div>
          <div className="text-xs uppercase tracking-[0.3em] text-sentinel-muted">
            First launch - create your account
          </div>
        </div>
        <p className="mb-4 text-xs leading-relaxed text-sentinel-muted">
          No accounts exist yet. Choose who this first user is. This screen appears
          once; afterwards every launch signs in normally.
        </p>
        {shown && (
          <p className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-200">
            {shown}
          </p>
        )}
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setLocalError(null);
            if (!valid) {
              setLocalError(
                password !== confirm
                  ? "Passwords do not match"
                  : "Username >= 3 chars; password >= 10 chars with a letter and a digit",
              );
              return;
            }
            await register({
              username: username.trim(),
              display_name: displayName.trim() || username.trim(),
              password,
              role,
            });
          }}
          className="space-y-3"
        >
          <input
            autoFocus
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="username"
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <input
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="display name (optional)"
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password (10+ chars, letter + digit)"
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            placeholder="confirm password"
            className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-500/60"
          />
          <div className="grid grid-cols-2 gap-2 pt-1">
            {([
              ["admin", "Administrator", "full access: response actions, users, deception"],
              ["viewer", "Normal user", "read-only dashboards and investigations"],
            ] as const).map(([value, label, hint]) => (
              <button
                key={value}
                type="button"
                onClick={() => setRole(value)}
                className={`rounded-lg border p-2 text-left text-xs transition-colors ${
                  role === value
                    ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-100"
                    : "border-sentinel-border text-slate-300 hover:bg-white/5"
                }`}
              >
                <div className="text-sm font-semibold">{label}</div>
                <div className="mt-0.5 text-[10px] text-sentinel-muted">{hint}</div>
              </button>
            ))}
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg border border-cyan-500/50 bg-cyan-600 py-2 text-sm font-semibold text-white transition-colors hover:bg-cyan-500 disabled:opacity-50"
          >
            {loading ? "Creating account…" : "Create account and sign in"}
          </button>
        </form>
        <p className="mt-4 text-center text-[11px] text-sentinel-muted">
          Credentials are stored only in this local database - nothing is printed or sent anywhere.
        </p>
      </div>
    </div>
  );
}