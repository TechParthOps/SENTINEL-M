import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Button, Card, ErrorBox, Spinner } from "../components/ui";
import { formatTime } from "../lib/format";

interface Report {
  generated_at: string;
  window_hours: number;
  events: { total: number; per_second_30m: number };
  alerts: {
    total: number;
    by_status: Record<string, number>;
    open: number;
    by_severity: Record<string, number>;
  };
  incidents: { total: number; open: number; critical: number };
  intel: { indicators_total: number; indicators_active: number; event_hits_24h: number };
  top_rules_24h: { rule_id: string; count: number }[];
  top_rules_all: { rule_id: string; count: number }[];
  response: { pending: number; executed: number; verified: number; rolled_back: number };
}

const SEV_LABEL: Record<string, string> = {
  "1": "informational", "2": "low", "3": "medium", "4": "high", "5": "critical",
};

/** Builds a report object from real endpoint data (no synthetic numbers). */
async function buildReport(hours: number): Promise<Report> {
  const [stats, alerts, incidentsRes, actionsRes] = await Promise.all([
    api.get<{
      events: { total: number; per_second_30m: number };
      alerts: { total: number; by_status: Record<string, number>; open: number };
      incidents: { total: number; open: number; critical: number };
      intel: { indicators_total: number; indicators_active: number; event_hits_24h: number };
      top_rules_24h: { rule_id: string; count: number }[];
    }>("/stats/overview"),
    api.get<{ alerts: { rule_id: string; severity_id: number; time: string; status: string }[] }>("/alerts?limit=2000"),
    api.get<{ incidents: { status: string; severity_id: number }[] }>("/incidents?limit=500"),
    api.get<{ actions: { status: string }[] }>("/response/actions?limit=500").catch(() => ({ actions: [] })),
  ]);

  const bySeverity: Record<string, number> = {};
  for (const a of alerts.alerts) {
    const key = String(a.severity_id);
    bySeverity[key] = (bySeverity[key] ?? 0) + 1;
  }

  // long-window rule counts from the full alert list
  const ruleCounts: Record<string, number> = {};
  for (const a of alerts.alerts) {
    ruleCounts[a.rule_id] = (ruleCounts[a.rule_id] ?? 0) + 1;
  }
  const topAll = Object.entries(ruleCounts)
    .map(([rule_id, count]) => ({ rule_id, count }))
    .sort((x, y) => y.count - x.count)
    .slice(0, 8);

  const response = { pending: 0, executed: 0, verified: 0, rolled_back: 0 };
  for (const a of actionsRes.actions ?? []) {
    if (a.status === "requested" || a.status === "approved") response.pending += 1;
    if (a.status === "executed") response.executed += 1;
    if (a.status === "verified") response.verified += 1;
    if (a.status === "rolled_back") response.rolled_back += 1;
  }
  void incidentsRes; // incident totals come from /stats/overview (server-side counts)

  return {
    generated_at: new Date().toISOString(),
    window_hours: hours,
    events: { total: stats.events.total, per_second_30m: stats.events.per_second_30m },
    alerts: {
      total: stats.alerts.total,
      by_status: stats.alerts.by_status,
      open: stats.alerts.open,
      by_severity: bySeverity,
    },
    incidents: {
      total: stats.incidents.total,
      open: stats.incidents.open,
      critical: stats.incidents.critical,
    },
    intel: {
      indicators_total: stats.intel.indicators_total,
      indicators_active: stats.intel.indicators_active,
      event_hits_24h: stats.intel.event_hits_24h,
    },
    top_rules_24h: stats.top_rules_24h,
    top_rules_all: topAll,
    response,
  };
}

function download(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportsPage() {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await buildReport(24));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to build the report");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!report || loading) return <Spinner label="Building report from live data…" />;

  const stamp = report.generated_at.slice(0, 19).replace(/[:T]/g, "-");

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Reports</h1>
          <p className="text-sm text-sentinel-muted">
            Security posture report generated from the live database — every number traces to
            stored events, alerts, incidents, indicators and response actions.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" onClick={load}>Regenerate</Button>
          <Button onClick={() => download(`sentinel-report-${stamp}.json`, JSON.stringify(report, null, 2), "application/json")}>
            Download JSON
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              const rows = [
                ["section", "metric", "value"],
                ["events", "total", report.events.total],
                ["alerts", "total", report.alerts.total],
                ["alerts", "open", report.alerts.open],
                ["incidents", "total", report.incidents.total],
                ["incidents", "open", report.incidents.open],
                ["intel", "indicators_active", report.intel.indicators_active],
                ...report.top_rules_all.map((r) => ["rule", r.rule_id, r.count] as (string | number)[]),
              ];
              const csv = rows.map((r) => r.join(",")).join("\n");
              download(`sentinel-report-${stamp}.csv`, csv, "text/csv");
            }}
          >
            Download CSV
          </Button>
        </div>
      </header>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {[
          ["Events retained", report.events.total, "all-time ingest volume"],
          ["Alerts", `${report.alerts.total}`, `${report.alerts.open} open · ${report.alerts.by_status.ack ?? 0} acknowledged`],
          ["Incidents", `${report.incidents.total}`, `${report.incidents.open} open · ${report.incidents.critical} critical`],
          ["Active indicators", report.intel.indicators_active, `of ${report.intel.indicators_total} · ${report.intel.event_hits_24h} hits/24h`],
        ].map(([label, value, hint]) => (
          <Card key={String(label)}>
            <p className="text-xs text-sentinel-muted">{label}</p>
            <p className="mt-1 text-2xl font-semibold text-cyan-200">{value}</p>
            <p className="mt-1 text-[11px] text-slate-500">{hint}</p>
          </Card>
        ))}
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Severity distribution" subtitle="All retained alerts">
          <div className="space-y-2">
            {Object.entries(report.alerts.by_severity)
              .sort((a, b) => Number(b[0]) - Number(a[0]))
              .map(([sev, count]) => {
                const max = Math.max(...Object.values(report.alerts.by_severity), 1);
                return (
                  <div key={sev} className="flex items-center gap-2 text-xs">
                    <span className="w-24 text-slate-400">{SEV_LABEL[sev] ?? `sev ${sev}`}</span>
                    <div className="h-3 flex-1 rounded bg-sentinel-bg">
                      <div className="h-3 rounded bg-cyan-500/70" style={{ width: `${(count / max) * 100}%` }} />
                    </div>
                    <span className="w-10 text-right font-mono text-slate-300">{count}</span>
                  </div>
                );
              })}
            {Object.keys(report.alerts.by_severity).length === 0 && (
              <p className="text-xs text-slate-500">No alerts recorded yet.</p>
            )}
          </div>
        </Card>

        <Card title="Top detection rules" subtitle="Retained alert counts (all-time)">
          {report.top_rules_all.length === 0 ? (
            <p className="text-xs text-slate-500">No alerts recorded yet.</p>
          ) : (
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr className="text-left text-sentinel-muted">
                  <th className="px-2 py-1">Rule</th>
                  <th className="px-2 py-1">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {report.top_rules_all.map((r) => (
                  <tr key={r.rule_id} className="border-t border-sentinel-border/40">
                    <td className="px-2 py-1 font-mono text-cyan-200">{r.rule_id}</td>
                    <td className="px-2 py-1 text-slate-300">{r.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Response actions" subtitle="From the approval workflow">
          <dl className="space-y-1 text-sm">
            <div className="flex justify-between"><dt className="text-sentinel-muted">Pending (requested/approved)</dt><dd className="text-slate-200">{report.response.pending}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Executed</dt><dd className="text-slate-200">{report.response.executed}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Verified</dt><dd className="text-slate-200">{report.response.verified}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Rolled back</dt><dd className="text-slate-200">{report.response.rolled_back}</dd></div>
          </dl>
        </Card>

        <Card title="Report metadata">
          <dl className="space-y-1 text-sm">
            <div className="flex justify-between"><dt className="text-sentinel-muted">Generated</dt><dd className="text-slate-200">{formatTime(report.generated_at)}</dd>
            </div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Window</dt><dd className="text-slate-200">last {report.window_hours} h highlights, totals all-time</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Events/sec (30 min)</dt><dd className="text-slate-200">{report.events.per_second_30m}</dd></div>
          </dl>
          <p className="mt-3 text-xs text-sentinel-muted">
            Exports are JSON or CSV snapshots of this page — shareable with auditors without
            exposing raw event payloads.
          </p>
        </Card>
      </div>
    </div>
  );
}