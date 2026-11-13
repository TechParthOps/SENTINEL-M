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
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  restore: () => Promise<void>;
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  loading: false,
  error: null,
  async login(username, password) {
    set({ loading: true, error: null });
    try {
      const res = await api.post<{ access_token: string }>("/auth/login", { username, password });
      setToken(res.access_token);
      const me = await api.get<Me>("/auth/me");
      set({ user: me, loading: false });
      return true;
    } catch (e) {
      set({ loading: false, error: e instanceof Error ? e.message : "login failed" });
      return false;
    }
  },
  logout() {
    setToken(null);
    set({ user: null });
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