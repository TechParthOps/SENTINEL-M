import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, Spinner, ErrorBox } from "../components/ui";
import { formatTime, severityClass, severityLabel, timeAgo } from "../lib/format";

interface AlertRow {
  id: string;
  time: string;
  rule_id: string;
  rule_title: string;
  category: string;
  severity_id: number;
  entity_key: string;
  entity_type: string;
  attack_ids: string[];
  status: string;
  message: string;
  incident_id: string | null;
}

export default function Alerts() {
  const user = useAuth((s) => s.user);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const q = status ? `?status=${status}&limit=200` : "?limit=200";
      const res = await api.get<{ total: number; alerts: AlertRow[] }>(`/alerts${q}`);
      setAlerts(res.alerts);
      setTotal(res.total);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load alerts");
    }
  }, [status]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  async function setAlertStatus(id: string, next: string) {
    setBusy(id);
    try {
      await api.patch(`/alerts/${id}`, { status: next });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "status update failed");
    } finally {
      setBusy(null);
    }
  }

  const canWork = canAct(user?.role, "analyst");

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Threat Detection</h1>
          <p className="text-sm text-sentinel-muted">
            {total} deterministic detections · every alert cites its rule and evidence events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-sentinel-muted">Status</label>
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
          >
            <option value="">all</option>
            <option value="new">new</option>
            <option value="ack">ack</option>
            <option value="investigating">investigating</option>
            <option value="resolved">resolved</option>
            <option value="closed">closed</option>
            <option value="false_positive">false positive</option>
          </select>
        </div>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      <Card>
        {total === 0 && !error ? (
          <Empty>No alerts yet — detection rules are armed and evaluating.</Empty>
        ) : (
          <div className="space-y-2">
            {alerts.map((a) => (
              <article
                key={a.id}
                className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={severityClass(a.severity_id)}>
                    {severityLabel(a.severity_id)} · {a.severity_id}
                  </Badge>
                  <span className="font-mono text-xs text-cyan-300">{a.rule_id}</span>
                  <span className="text-sm font-medium text-slate-100">{a.rule_title}</span>
                  <span className="ml-auto text-xs text-slate-500" title={formatTime(a.time)}>
                    {timeAgo(a.time)}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-400">
                  <span>
                    entity <span className="font-mono text-slate-300">{a.entity_key}</span> ({a.entity_type})
                  </span>
                  <span>
                    ATT&CK: <span className="font-mono text-amber-200">{a.attack_ids.join(", ") || "—"}</span>
                  </span>
                  <span>category {a.category}</span>
                  {a.incident_id && <span className="text-cyan-300">incident {a.incident_id.slice(0, 8)}</span>}
                </div>
                <p className="mt-1 text-sm text-slate-300">{a.message}</p>
                <div className="mt-2 flex items-center gap-2">
                  <Badge className="border-slate-500/40 bg-slate-600/20 text-slate-300">{a.status}</Badge>
                  {canWork && (
                    <>
                      <Button variant="ghost" onClick={() => setAlertStatus(a.id, "ack")} disabled={busy === a.id}>
                        Acknowledge
                      </Button>
                      <Button variant="ghost" onClick={() => setAlertStatus(a.id, "investigating")} disabled={busy === a.id}>
                        Investigate
                      </Button>
                      <Button variant="ghost" onClick={() => setAlertStatus(a.id, "false_positive")} disabled={busy === a.id}>
                        Mark false positive
                      </Button>
                    </>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
      </Card>

      {!canWork && (
        <p className="text-xs text-sentinel-muted">
          Your role ({user?.role}) has read-only access to detections.
        </p>
      )}
    </div>
  );
}