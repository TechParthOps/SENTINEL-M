import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Card, Spinner, Empty, ErrorBox } from "../components/ui";
import { formatTime } from "../lib/format";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Link } from "react-router-dom";

interface OverviewStats {
  events: { total: number; per_second_30m: number; timeline_30m: { t: string; count: number }[]; by_class: Record<string, number> };
  alerts: { total: number; by_status: Record<string, number>; open: number };
  incidents: { total: number; open: number; critical: number };
  assets: { total: number; sample: number; auto_registered: number; telemetry_seen: number };
  top_rules_24h: { rule_id: string; count: number }[];
}

export default function Overview() {
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [badges, setBadges] = useState<Record<string, number>>({});

  useEffect(() => {
    api
      .get<OverviewStats>("/stats/overview")
      .then(setStats)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    // honest "no data" badges: counts of alert statuses
    if (stats) setBadges(stats.alerts.by_status || {});
  }, [stats]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!stats) return <Spinner label="Loading live security posture…" />;

  const timeline = stats.events.timeline_30m.map((b, i) => ({
    name: i,
    count: b.count,
  }));

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Security Overview</h1>
          <p className="text-sm text-sentinel-muted">
            Live posture from the detection, correlation and inventory engines.
          </p>
        </div>
        <Link to="/live" className="text-sm text-cyan-300 underline hover:text-cyan-200">
          Open live operations →
        </Link>
      </header>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Metric label="Active incidents" value={stats.incidents.open} tone={stats.incidents.open > 0 ? "warn" : "ok"} hint={`${stats.incidents.critical} critical severity`} />
        <Metric label="Open alerts" value={stats.alerts.open} tone={stats.alerts.open > 0 ? "warn" : "ok"} hint={`${stats.alerts.total} total`} />
        <Metric label="Events ingested" value={stats.events.total} tone="ok" hint={`${stats.events.per_second_30m} events/sec (30 min)`} />
        <Metric label="Assets tracked" value={stats.assets.total} tone="ok" hint={`${stats.assets.telemetry_seen} seen live · ${stats.assets.sample} sample`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Event throughput — last 30 minutes" subtitle="Per-minute buckets from normalized events" className="lg:col-span-2">
          {stats.events.total === 0 ? (
            <Empty>No events ingested yet. Ingest telemetry to populate this chart.</Empty>
          ) : (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeline}>
                  <defs>
                    <linearGradient id="ev" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#22d3ee" stopOpacity={0.5} />
                      <stop offset="100%" stopColor="#22d3ee" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1e2a45" strokeDasharray="3 3" />
                  <XAxis dataKey="name" tick={false} stroke="#475569" />
                  <YAxis stroke="#475569" allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: "#111a2b", border: "1px solid #263254", borderRadius: 8 }}
                    labelFormatter={(v) => `bucket #${v}`}
                  />
                  <Area type="monotone" dataKey="count" stroke="#22d3ee" fill="url(#ev)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card title="Event classes" subtitle="Normalized (OCSF-aligned) distribution">
          {Object.keys(stats.events.by_class).length === 0 ? (
            <Empty>No events yet.</Empty>
          ) : (
            <ul className="space-y-2">
              {Object.entries(stats.events.by_class).map(([cls, n]) => (
                <li key={cls} className="flex items-center justify-between text-sm">
                  <span className="text-slate-300">{cls}</span>
                  <span className="font-mono text-cyan-200">{n}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Top firing rules (24h)" subtitle="Deterministic detection rules">
          {stats.top_rules_24h.length === 0 ? (
            <Empty>No detections in the last 24 hours.</Empty>
          ) : (
            <ul className="space-y-2">
              {stats.top_rules_24h.map((r) => (
                <li key={r.rule_id} className="flex items-center justify-between text-sm">
                  <Link to="/rules" className="font-mono text-xs text-cyan-300 hover:underline">
                    {r.rule_id}
                  </Link>
                  <span className="font-mono text-slate-300">{r.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card title="Alert workflow" subtitle="Analyst state distribution">
          {stats.alerts.total === 0 ? (
            <Empty>No alerts yet.</Empty>
          ) : (
            <ul className="space-y-2">
              {Object.entries(badges).map(([status, count]) => (
                <li key={status} className="flex items-center justify-between text-sm">
                  <span className="text-slate-300">{status}</span>
                  <span className="font-mono text-slate-300">{count}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <p className="text-xs text-sentinel-muted">
        All figures above are computed from real ingested events, alerts and incidents — nothing is
        simulated. Last computed {formatTime(new Date().toISOString())}.
      </p>
    </div>
  );
}

function Metric({ label, value, tone, hint }: { label: string; value: number; tone: "ok" | "warn"; hint: string }) {
  const color = tone === "warn" ? "text-amber-300" : "text-emerald-300";
  return (
    <div className="rounded-xl border border-sentinel-border bg-sentinel-surface/80 p-4">
      <div className="text-xs uppercase tracking-wider text-sentinel-muted">{label}</div>
      <div className={`mt-1 text-3xl font-bold ${color}`}>{value}</div>
      <div className="mt-1 text-xs text-slate-400">{hint}</div>
    </div>
  );
}