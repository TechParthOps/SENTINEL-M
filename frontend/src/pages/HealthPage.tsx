import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Button, Card, Empty, Spinner, ErrorBox, Badge } from "../components/ui";
import { formatTime } from "../lib/format";

interface HealthModule {
  status: "ok" | "degraded" | "error";
  [key: string]: unknown;
}

export default function HealthPage() {
  const user = useAuth((s) => s.user);
  const isAdmin = canAct(user?.role, "admin");
  const [health, setHealth] = useState<{ status: string; modules: Record<string, HealthModule>; checked_at: number } | null>(null);
  const [audit, setAudit] = useState<{ entries: unknown[]; chain: { valid: boolean; entries: number } } | null>(null);
  const [info, setInfo] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setHealth(await api.get("/health"));
      setInfo(await api.get("/system/info"));
      if (isAdmin) setAudit(await api.get("/audit?limit=25"));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load system status");
    }
  }, [isAdmin]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!health || !info) return <Spinner label="Checking module health…" />;

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">System Health</h1>
          <p className="text-sm text-sentinel-muted">
            Live module registry · checked {formatTime(new Date(health.checked_at * 1000).toISOString())}
          </p>
        </div>
        <Button variant="ghost" onClick={load}>Re-check</Button>
      </header>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {Object.entries(health.modules).map(([name, mod]) => (
          <Card key={name}>
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm text-cyan-200">{name}</span>
              <Badge
                className={
                  mod.status === "ok"
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                    : mod.status === "degraded"
                      ? "border-amber-500/40 bg-amber-500/15 text-amber-200"
                      : "border-red-500/40 bg-red-500/15 text-red-200"
                }
              >
                {mod.status}
              </Badge>
            </div>
            <pre className="mt-2 overflow-x-auto text-[11px] text-slate-400">
              {JSON.stringify(Object.fromEntries(Object.entries(mod).filter(([k]) => k !== "status")), null, 1)}
            </pre>
          </Card>
        ))}
      </div>

      {info.secret_key_is_insecure ? (
        <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200">
          Warning: SENTINEL_SECRET_KEY is still the development default. Set a strong key before
          real deployments (see backend/.env.example).
        </p>
      ) : null}

      {isAdmin && audit && (
        <Card
          title="Audit log (admin only)"
          subtitle={`Hash-chained, append-only · chain valid: ${audit.chain.valid} · ${audit.chain.entries} entries`}
        >
          {audit.entries.length === 0 ? (
            <Empty>No audit entries yet.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse font-mono text-xs">
                <thead>
                  <tr className="text-left text-sentinel-muted">
                    <th className="px-2 py-1">Seq</th>
                    <th className="px-2 py-1">Time</th>
                    <th className="px-2 py-1">Action</th>
                    <th className="px-2 py-1">Actor</th>
                    <th className="px-2 py-1">Entry hash</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.entries.map((e) => {
                    const entry = e as { seq: number; ts: string; action: string; actor: string; entry_hash: string };
                    return (
                      <tr key={entry.seq} className="border-t border-sentinel-border/40">
                        <td className="px-2 py-1">{entry.seq}</td>
                        <td className="px-2 py-1">{entry.ts}</td>
                        <td className="px-2 py-1 text-cyan-200">{entry.action}</td>
                        <td className="px-2 py-1">{entry.actor}</td>
                        <td className="px-2 py-1 text-slate-500">{entry.entry_hash.slice(0, 16)}…</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {!isAdmin && (
        <p className="text-xs text-sentinel-muted">
          Audit log inspection requires the <code>admin</code> role.
        </p>
      )}
    </div>
  );
}