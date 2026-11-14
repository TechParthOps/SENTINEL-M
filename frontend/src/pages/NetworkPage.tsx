import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Card, Empty, Spinner, ErrorBox, Badge } from "../components/ui";
import { formatTime, severityLabel, statusClass, timeAgo } from "../lib/format";
import { Table } from "../components/ui";

interface NetEvent {
  id: string;
  time: string;
  src_ip: string | null;
  dst_ip: string | null;
  message: string;
  severity_id: number;
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

const NETWORK_RULES = [
  "NET-BEACON-001",
  "NET-PORTSCAN-001",
  "NET-C2-DGA-001",
  "NET-DNSTUNNEL-001",
  "NET-EXFIL-001",
  "WEB-SQLI-001",
  "WEB-XSS-001",
  "WEB-SSRF-001",
  "WEB-TRAVERSAL-001",
];

export default function NetworkPage() {
  const [events, setEvents] = useState<NetEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [classFilter, setClassFilter] = useState("network_activity");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [ev, al] = await Promise.all([
        api.get<{ events: NetEvent[] }>(
          `/events?limit=40&class_name=${classFilter === "all" ? "" : classFilter}`
        ),
        api.get<{ alerts: Alert[] }>("/alerts?limit=200"),
      ]);
      setEvents(ev.events);
      setAlerts(al.alerts.filter((a) => NETWORK_RULES.includes(a.rule_id)));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load network data");
    }
  }, [classFilter]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Network Security</h1>
          <p className="text-sm text-sentinel-muted">
            Network/DNS/HTTP telemetry with the Phase-2 network detection set. Covers beaconing,
            port scans, DGA indicators, DNS tunneling, exfiltration volume and web attack patterns.
          </p>
        </div>
        <select
          value={classFilter}
          onChange={(e) => setClassFilter(e.target.value)}
          className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
        >
          <option value="network_activity">network</option>
          <option value="dns_activity">DNS</option>
          <option value="web_resource_access_activity">HTTP / web</option>
          <option value="all">all classes</option>
        </select>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      <Card title="Recent telemetry" subtitle="Newest 40 events in the selected class">
        {events.length === 0 ? (
          <Empty>No matching events. Ingest network/DNS/HTTP telemetry to populate this view.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["Time", "Source", "Destination", "Message"]}
              rows={events.map((e) => [
                <span className="font-mono text-xs text-slate-400" title={formatTime(e.time)}>{timeAgo(e.time)}</span>,
                <span className="font-mono text-xs text-cyan-200">{e.src_ip ?? "—"}</span>,
                <span className="font-mono text-xs text-slate-300">{e.dst_ip ?? "—"}</span>,
                <span className="text-slate-300">{e.message}</span>,
              ])}
            />
          </div>
        )}
      </Card>

      <Card title="Network detections" subtitle="Alerts from the network/web rule set">
        {alerts.length === 0 ? (
          <Empty>No network or web detections in the retained alert window.</Empty>
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
    </div>
  );
}