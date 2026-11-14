import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../store/auth";
import { useEffect } from "react";
import { useLive } from "../store/live";

interface NavItem {
  to: string;
  label: string;
  status: "implemented" | "planned";
  phase?: number;
}

export const NAV_ITEMS: NavItem[] = [
  { to: "/overview", label: "Overview", status: "implemented" },
  { to: "/live", label: "Live Operations", status: "implemented" },
  { to: "/virtual-office", label: "3D Virtual Office", status: "implemented" },
  { to: "/threat-detection", label: "Threat Detection", status: "implemented" },
  { to: "/incidents", label: "Incidents", status: "implemented" },
  { to: "/hunting", label: "Threat Hunting", status: "implemented" },
  { to: "/network", label: "Network Security", status: "implemented" },
  { to: "/endpoint", label: "Endpoint Security", status: "implemented" },
  { to: "/identity", label: "Identity Security", status: "implemented" },
  { to: "/ai-security", label: "AI Security", status: "implemented" },
  { to: "/multimodal", label: "Multimodal Forensics", status: "implemented" },
  { to: "/intelligence", label: "Threat Intelligence", status: "implemented" },
  { to: "/malware", label: "Malware Analysis", status: "implemented" },
  { to: "/agents", label: "Autonomous Agents", status: "implemented" },
  { to: "/deception", label: "Deception Lab", status: "implemented" },
  { to: "/forensics", label: "Digital Forensics", status: "planned", phase: 4 },
  { to: "/assets", label: "Assets and Infrastructure", status: "implemented" },
  { to: "/rules", label: "Detection Rules", status: "implemented" },
  { to: "/playbooks", label: "Response Playbooks", status: "implemented" },
  { to: "/reports", label: "Reports", status: "planned", phase: 7 },
  { to: "/integrations", label: "Integrations", status: "planned", phase: 2 },
  { to: "/health", label: "System Health", status: "implemented" },
  { to: "/settings", label: "Settings", status: "implemented" },
];

export default function AppLayout() {
  const user = useAuth((s) => s.user);
  const logout = useAuth((s) => s.logout);
  const connect = useLive((s) => s.connect);
  const connected = useLive((s) => s.connected);

  useEffect(() => {
    if (user) {
      const dispose = connect();
      return dispose;
    }
  }, [user, connect]);

  return (
    <div className="flex h-full">
      <aside className="flex w-64 shrink-0 flex-col border-r border-sentinel-border bg-sentinel-surface">
        <div className="border-b border-sentinel-border px-4 py-4">
          <div className="text-lg font-bold tracking-wide text-cyan-300">SENTINEL-M</div>
          <div className="text-[11px] uppercase tracking-widest text-sentinel-muted">Cyber Defense Platform</div>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `mx-2 flex items-center justify-between rounded-lg px-3 py-1.5 text-sm transition-colors ${
                  isActive ? "bg-cyan-500/15 text-cyan-200" : "text-slate-300 hover:bg-white/5"
                }`
              }
            >
              <span>{item.label}</span>
              {item.status === "planned" && (
                <span className="rounded-full border border-slate-500/40 px-1.5 text-[10px] text-slate-400">
                  P{item.phase}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-sentinel-border px-4 py-3 text-xs text-sentinel-muted">
          <div className="flex items-center justify-between">
            <span>Live stream</span>
            <span className={connected ? "text-emerald-300" : "text-amber-300"}>
              {connected ? "connected" : "connecting…"}
            </span>
          </div>
          {user && (
            <div className="mt-2 flex items-center justify-between">
              <span className="text-slate-300">
                {user.username} <span className="text-slate-500">({user.role})</span>
              </span>
              <button onClick={logout} className="text-slate-400 underline hover:text-red-300">
                sign out
              </button>
            </div>
          )}
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto p-6">
        <Outlet />
      </main>
    </div>
  );
}