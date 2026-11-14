import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Badge, Card, Empty, ErrorBox, Spinner, Table } from "../components/ui";
import { severityLabel, statusClass, timeAgo } from "../lib/format";

interface Summary {
  auth_events_24h: number;
  successes_24h: number;
  failures_24h: number;
  distinct_users: number;
  geo_change_events_24h: number;
  users_with_geo_context: number;
  identity_alerts_24h: number;
  limitation: string;
}

interface AuthEvent {
  id: string;
  time: string;
  user: string | null;
  message: string;
  severity_id: number;
  raw: Record<string, unknown>;
}

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

const IDENTITY_RULES = [
  "ID-IMPOSSIBLE-TRAVEL-001",
  "AUTH-BRUTEFORCE-001",
  "AUTH-SUSPICIOUS-LOGON-003",
  "AUTH-PASSWORDSPRAY-002",
];

export default function IdentityPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [events, setEvents] = useState<AuthEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [sm, ev, al] = await Promise.all([
        api.get<Summary>("/identity/summary"),
        api.get<{ events: AuthEvent[] }>("/events?limit=60&class_name=authentication"),
        api.get<{ alerts: Alert[] }>("/alerts?limit=200"),
      ]);
      setSummary(sm);
      setEvents(ev.events);
      setAlerts(al.alerts.filter((a) => IDENTITY_RULES.includes(a.rule_id)));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load identity data");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  if (!summary && !error) return <Spinner />;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Identity Security</h1>
        <p className="text-sm text-sentinel-muted">
          Authentication telemetry with Phase-2 identity detections: impossible travel (geo-annotated
          sessions), brute force, password spray and suspicious logon patterns.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {summary && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <Card title="Auth events (24h)">
              <div className="text-3xl font-semibold text-cyan-300">{summary.auth_events_24h}</div>
              <div className="mt-1 text-xs text-sentinel-muted">
                {summary.successes_24h} success · {summary.failures_24h} failed
              </div>
            </Card>
            <Card title="Distinct users">
              <div className="text-3xl font-semibold text-cyan-300">{summary.distinct_users}</div>
              <div className="mt-1 text-xs text-sentinel-muted">observed in telemetry</div>
            </Card>
            <Card title="Geo-change signals (24h)">
              <div className="text-3xl font-semibold text-cyan-300">{summary.geo_change_events_24h}</div>
              <div className="mt-1 text-xs text-sentinel-muted">
                across {summary.users_with_geo_context} geo-annotated users
              </div>
            </Card>
            <Card title="Identity detections (24h)">
              <div className="text-3xl font-semibold text-cyan-300">{summary.identity_alerts_24h}</div>
              <div className="mt-1 text-xs text-sentinel-muted">identity rule alerts</div>
            </Card>
          </div>

          <Card title="Coverage note" subtitle="Honest limitation (ADR-008)">
            <p className="text-sm text-slate-300">{summary.limitation}</p>
          </Card>

          <Card title="Identity detections" subtitle="Alerts from the identity/auth rule set">
            {alerts.length === 0 ? (
              <Empty>No identity detections in the retained alert window.</Empty>
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
                      entity <span className="font-mono text-slate-300">{a.entity_key}</span> ·{" "}
                      {a.attack_ids.join(", ")} · {timeAgo(a.time)}
                    </div>
                    <p className="mt-1 text-sm text-slate-300">{a.message}</p>
                  </article>
                ))}
              </div>
            )}
          </Card>

          <Card title="Recent authentication telemetry" subtitle="Newest 60 authentication events">
            {events.length === 0 ? (
              <Empty>No auth events retained. Ingest authentication telemetry to populate this view.</Empty>
            ) : (
              <div className="overflow-x-auto">
                <Table
                  head={["Time", "User", "Outcome", "Message"]}
                  rows={events.map((e) => {
                    const outcome = String((e.raw as { outcome?: string })?.outcome ?? "—");
                    return [
                      <span className="font-mono text-xs text-slate-400">{timeAgo(e.time)}</span>,
                      <span className="font-mono text-xs text-cyan-200">{e.user ?? "—"}</span>,
                      <span className={outcome === "success" ? "text-emerald-300" : "text-red-300"}>{outcome}</span>,
                      <span className="text-slate-300">{e.message}</span>,
                    ];
                  })}
                />
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
