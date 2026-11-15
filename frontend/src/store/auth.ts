import { create } from "zustand";
import { api, getToken, setToken } from "../lib/api";

export type Role = "admin" | "analyst" | "viewer";

interface Me {
  id: number;
  username: string;
  display_name: string;
  role: Role;
}

interface AuthState {
  user: Me | null;
  loading: boolean;
  error: string | null;
  /** Phase 7: when the server answers a login with mfa_required, the step-up token
   * is kept here so the login form can collect the second factor. */
  mfaToken: string | null;
  /** First-launch bootstrap: null = unknown, true = no accounts exist yet. */
  needsSetup: boolean | null;
  /** Server policy: non-admin self-registration allowed? */
  allowSelfRegistration: boolean;
  checkBootstrap: () => Promise<void>;
  register: (account: {
    username: string;
    display_name: string;
    password: string;
    role: "admin" | "analyst" | "viewer";
  }) => Promise<boolean>;
  login: (username: string, password: string) => Promise<boolean>;
  verifyMfa: (code: string, recoveryCode?: string) => Promise<boolean>;
  clearMfa: () => void;
  logout: () => void;
  restore: () => Promise<void>;
}

export const useAuth = create<AuthState>((set, get) => ({
  user: null,
  loading: false,
  error: null,
  mfaToken: null,
  needsSetup: null,
  allowSelfRegistration: true,

  async checkBootstrap() {
    try {
      const res = await api.get<{ needs_setup: boolean; allow_self_registration: boolean }>(
        "/auth/bootstrap-status",
      );
      set({ needsSetup: res.needs_setup, allowSelfRegistration: res.allow_self_registration });
    } catch {
      set({ needsSetup: false }); // fail closed: show the normal login form
    }
  },

  async register({ username, display_name, password, role }) {
    set({ loading: true, error: null });
    try {
      await api.post("/auth/users", { username, password, display_name, role });
      // first account created - sign straight in with it
      return await get().login(username, password);
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : "registration failed" });
      return false;
    }
  },
  async login(username, password) {
    set({ loading: true, error: null, mfaToken: null });
    try {
      const res = await api.post<{ access_token: string; mfa_required?: boolean }>("/auth/login", { username, password });
      if (res.mfa_required) {
        set({ mfaToken: res.access_token, loading: false });
        return true;
      }
      setToken(res.access_token);
      const me = await api.get<Me>("/auth/me");
      set({ user: me, loading: false });
      return true;
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : "login failed" });
      return false;
    }
  },
  async verifyMfa(code, recoveryCode) {
    const token = get().mfaToken;
    if (!token) return false;
    set({ loading: true, error: null });
    try {
      const path = recoveryCode ? "/auth/mfa/recovery-login" : "/auth/mfa/verify";
      const body = recoveryCode
        ? { mfa_token: token, recovery_code: recoveryCode }
        : { mfa_token: token, code };
      const res = await api.post<{ access_token: string }>(path, body);
      setToken(res.access_token);
      const me = await api.get<Me>("/auth/me");
      set({ user: me, loading: false, mfaToken: null });
      return true;
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : "verification failed" });
      return false;
    }
  },
  clearMfa() {
    set({ mfaToken: null, error: null });
  },
  logout() {
    setToken(null);
    set({ user: null, needsSetup: null, mfaToken: null, error: null });
  },
  async restore() {
    if (!getToken()) return;
    try {
      const me = await api.get<Me>("/auth/me");
      set({ user: me });
    } catch {
      setToken(null);
    }
  },
}));

export function canAct(role: Role | undefined, minimum: Role): boolean {
  const rank = { viewer: 0, analyst: 1, admin: 2 } as const;
  if (!role) return false;
  return rank[role] >= rank[minimum];
}