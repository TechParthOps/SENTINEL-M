import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Button, Card, Empty, ErrorBox, Badge, Spinner } from "../components/ui";
import { severityLabel, statusClass, timeAgo } from "../lib/format";
import { useAuth } from "../store/auth";

interface Alert {
  id: string;
  time: string;
  rule_id: string;
  rule_title: string;
  severity_id: number;
  entity_key: string;
  attack_ids: string[];
  status: string;
  message: string;
}

const ENDPOINT_RULES = [
  "HOST-PS-ATTACK-001",
  "HOST-PERSIST-001",
  "HOST-CREDDUMP-001",
  "HOST-REGISTRY-PERSIST-001",
  "HOST-SVC-CREATE-001",
  "FILE-RANSOM-001",
  "ID-IMPOSSIBLE-TRAVEL-001",
];

export default function EndpointPage() {
  const user = useAuth((s) => s.user);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [classFilter, setClassFilter] = useState("process_activity");
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [al, ev] = await Promise.all([
        api.get<{ alerts: Alert[] }>("/alerts?limit=200"),
        api.get<{ events: Record<string, unknown>[] }>(
          `/events?limit=40&class_name=${classFilter === "all" ? "" : classFilter}`
        ),
      ]);
      setAlerts(al.alerts.filter((a) => ENDPOINT_RULES.includes(a.rule_id)));
      setEvents(ev.events);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load endpoint data");
    }
  }, [classFilter]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  async function setAlertStatus(id: string, status: string) {
    try {
      await api.patch(`/alerts/${id}`, { status });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "status update failed");
    }
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Endpoint Security</h1>
          <p className="text-sm text-sentinel-muted">
            Process, file and identity telemetry with host-focused detections: suspicious PowerShell,
            persistence, credential dumping, registry Run keys, service creation, ransomware velocity.
          </p>
        </div>
        <select
          value={classFilter}
          onChange={(e) => setClassFilter(e.target.value)}
          className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
        >
          <option value="process_activity">process</option>
          <option value="file_activity">file</option>
          <option value="authentication">authentication</option>
          <option value="all">all classes</option>
        </select>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      <Card title="Endpoint detections" subtitle="Host/identity rule alerts in the retained window">
        {alerts.length === 0 ? (
          <Empty>No endpoint detections right now.</Empty>
        ) : (
          <div className="space-y-2">
            {alerts.map((a) => (
              <article key={a.id} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={a.severity_id >= 5 ? "border-red-500/40 bg-red-500/15 text-red-200" : "border-amber-500/40 bg-amber-500/15 text-amber-200"}>
                    {severityLabel(a.severity_id)}
                  </Badge>
                  <span className="font-mono text-xs text-cyan-300">{a.rule_id}</span>
                  <span className="text-sm text-slate-200">{a.rule_title}</span>
                  <span className={`ml-auto rounded-full border px-2 text-[11px] ${statusClass(a.status)}`}>{a.status}</span>
                </div>
                <div className="mt-1 text-xs text-slate-400">
                  host <span className="font-mono text-slate-300">{a.entity_key}</span> · {a.attack_ids.join(", ")} · {timeAgo(a.time)}
                </div>
                <p className="mt-1 text-sm text-slate-300">{a.message}</p>
                {user && user.role !== "viewer" && (
                  <div className="mt-2 flex gap-2">
                    <Button variant="ghost" onClick={() => setAlertStatus(a.id, "ack")}>Ack</Button>
                    <Button variant="ghost" onClick={() => setAlertStatus(a.id, "investigating")}>Investigate</Button>
                  </div>
                )}
              </article>
            ))}
          </div>
        )}
      </Card>

      <Card title="Recent host telemetry" subtitle="Newest 40 events in the selected class">
        {events.length === 0 ? (
          <Empty>No matching events.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-sentinel-muted">
                  <th className="px-2 py-2">Time</th>
                  <th className="px-2 py-2">Host</th>
                  <th className="px-2 py-2">User</th>
                  <th className="px-2 py-2">Message</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={String(e.id)} className="border-t border-sentinel-border/40">
                    <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-slate-400">{timeAgo(String(e.time))}</td>
                    <td className="px-2 py-2 font-mono text-xs text-cyan-200">{String(e.host ?? "—")}</td>
                    <td className="px-2 py-2 text-xs text-slate-300">{String(e.user ?? "—")}</td>
                    <td className="max-w-md px-2 py-2 text-slate-300">{String(e.message)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}