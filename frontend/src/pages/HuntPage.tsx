import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Spinner, Table } from "../components/ui";
import { severityClass, severityLabel, timeAgo } from "../lib/format";

interface HuntEvent {
  id: string;
  time: string;
  class_name: string;
  message: string;
  host: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  user: string | null;
  severity_id: number;
}

interface HuntAlert {
  id: string;
  time: string;
  rule_id: string;
  rule_title: string;
  severity_id: number;
  entity_key: string;
  attack_ids: string[];
  status: string;
  incident_id: string | null;
}

interface HuntResponse {
  query: { q: string | null; class_name: string | null; host: string | null; hours: number };
  total_events: number;
  events: HuntEvent[];
  total_alerts: number;
  alerts: HuntAlert[];
}

export default function HuntPage() {
  const user = useAuth((s) => s.user);
  const canHunt = canAct(user?.role, "analyst");
  const [q, setQ] = useState("");
  const [hours, setHours] = useState(168);
  const [result, setResult] = useState<HuntResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const params = new URLSearchParams({ hours: String(hours) });
      if (q.trim()) params.set("q", q.trim());
      setResult(await api.get<HuntResponse>(`/hunt?${params.toString()}`));
    } catch (e) {
      setError(e instanceof Error ? e.message : "hunt failed");
    } finally {
      setBusy(false);
    }
  }, [q, hours]);

  useEffect(() => {
    run();
  }, []); // initial empty sweep

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Threat Hunting</h1>
        <p className="text-sm text-sentinel-muted">
          Read-only search over retained events and alerts: match an IOC, entity, user or free
          text within a lookback window. Hunting never mutates state.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {canHunt ? (
        <Card title="Hunt query" subtitle="Matched against observables, message, IPs, host and user fields">
          <div className="flex flex-wrap items-center gap-3">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && run()}
              placeholder="IOC / IP / domain / user / text… (empty = sweep window)"
              className="min-w-[280px] flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 font-mono text-sm text-slate-200"
            />
            <select
              value={hours}
              onChange={(e) => setHours(Number(e.target.value))}
              className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
            >
              <option value={24}>last 24h</option>
              <option value={168}>last 7d</option>
              <option value={720}>last 30d</option>
              <option value={2160}>last 90d</option>
            </select>
            <Button onClick={run} disabled={busy}>{busy ? "Hunting…" : "Run hunt"}</Button>
          </div>
        </Card>
      ) : (
        <Card title="Hunt query">
          <Empty>Threat hunting requires the analyst role.</Empty>
        </Card>
      )}

      {result && (
        <>
          <div className="text-sm text-slate-400">
            <span className="text-cyan-300">{result.total_events}</span> matching events ·{" "}
            <span className="text-cyan-300">{result.total_alerts}</span> related alerts in the
            last {result.query.hours}h
          </div>

          <Card title="Related alerts">
            {result.alerts.length === 0 ? (
              <Empty>No alerts matched this hunt.</Empty>
            ) : (
              <div className="overflow-x-auto">
                <Table
                  head={["Time", "Rule", "Severity", "Entity", "ATT&CK"]}
                  rows={result.alerts.map((a) => [
                    <span className="font-mono text-xs text-slate-400">{timeAgo(a.time)}</span>,
                    <span className="text-slate-200">
                      <span className="font-mono text-xs text-cyan-300">{a.rule_id}</span>{" "}
                      {a.rule_title}
                    </span>,
                    <Badge className={severityClass(a.severity_id)}>{severityLabel(a.severity_id)}</Badge>,
                    <span className="font-mono text-xs text-slate-300">{a.entity_key}</span>,
                    <span className="text-xs text-slate-400">{a.attack_ids.join(", ") || "—"}</span>,
                  ])}
                />
              </div>
            )}
          </Card>

          <Card title="Matching events" subtitle={`Showing up to ${result.events.length}`}>
            {result.events.length === 0 ? (
              <Empty>No events matched this hunt query.</Empty>
            ) : (
              <div className="overflow-x-auto">
                <Table
                  head={["Time", "Class", "Host", "Source", "Destination", "Message"]}
                  rows={result.events.map((e) => [
                    <span className="font-mono text-xs text-slate-400">{timeAgo(e.time)}</span>,
                    <span className="text-slate-300">{e.class_name}</span>,
                    <span className="font-mono text-xs text-slate-300">{e.host ?? "—"}</span>,
                    <span className="font-mono text-xs text-cyan-200">{e.src_ip ?? "—"}</span>,
                    <span className="font-mono text-xs text-slate-300">{e.dst_ip ?? "—"}</span>,
                    <span className="text-slate-300">{e.message}</span>,
                  ])}
                />
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
