import { useEffect, useState, useCallback } from "react";
import { api } from "../lib/api";
import { useLive } from "../store/live";
import { Badge, Card, Empty, Spinner, ErrorBox } from "../components/ui";
import { formatTime, severityLabel, timeAgo } from "../lib/format";

interface EventRow {
  id: string;
  time: string;
  class_name: string;
  severity_id: number;
  message: string;
  host: string | null;
  src_ip: string | null;
  user: string | null;
  source_product: string;
}

const CLASS_FILTERS = ["", "authentication", "process_activity", "network_activity", "dns_activity", "file_activity", "web_resource_access_activity", "generic"];

export default function LiveOps() {
  const connected = useLive((s) => s.connected);
  const liveEvents = useLive((s) => s.events);
  const [classFilter, setClassFilter] = useState("");
  const [rows, setRows] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const q = new URLSearchParams({ limit: "60" });
      if (classFilter) q.set("class_name", classFilter);
      const res = await api.get<{ total: number; events: EventRow[] }>(`/events?${q}`);
      setRows(res.events);
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load events");
    }
  }, [classFilter]);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  // Live stream prepends freshly ingested events (dedupe by id against REST rows)
  const merged: EventRow[] = [
    ...(classFilter === "" ? liveEvents.map((e) => ({
      id: e.id,
      time: e.time,
      class_name: e.class_name,
      severity_id: e.severity_id,
      message: e.message,
      host: e.host,
      src_ip: e.src_ip,
      user: null,
      source_product: e.source_product || "live",
    })) : []),
    ...rows,
  ].filter((e, i, arr) => arr.findIndex((x) => x.id === e.id) === i).slice(0, 100);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Live Operations</h1>
          <p className="text-sm text-sentinel-muted">
            {total.toLocaleString()} normalized events · live stream{" "}
            <span className={connected ? "text-emerald-300" : "text-amber-300"}>
              {connected ? "connected" : "connecting…"}
            </span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-sentinel-muted">Class</label>
          <select
            value={classFilter}
            onChange={(e) => setClassFilter(e.target.value)}
            className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
          >
            {CLASS_FILTERS.map((c) => (
              <option key={c} value={c}>
                {c || "all classes"}
              </option>
            ))}
          </select>
        </div>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      <Card title="Event stream" subtitle="Newest first · ingestion + live WebSocket feed">
        {merged.length === 0 ? (
          <Empty>No events match the current filter.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-sentinel-muted">
                  <th className="px-2 py-2">Time</th>
                  <th className="px-2 py-2">Class</th>
                  <th className="px-2 py-2">Sev</th>
                  <th className="px-2 py-2">Host / User</th>
                  <th className="px-2 py-2">Source IP</th>
                  <th className="px-2 py-2">Message</th>
                  <th className="px-2 py-2">Source</th>
                </tr>
              </thead>
              <tbody>
                {merged.map((e) => (
                  <tr key={e.id} className="border-t border-sentinel-border/40 align-top hover:bg-cyan-500/[0.05]">
                    <td className="whitespace-nowrap px-2 py-2 font-mono text-xs text-slate-400" title={formatTime(e.time)}>
                      {timeAgo(e.time)}
                    </td>
                    <td className="px-2 py-2">
                      <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[11px] text-cyan-200">
                        {e.class_name}
                      </span>
                    </td>
                    <td className="px-2 py-2 text-xs text-slate-300">{severityLabel(e.severity_id)}</td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">
                      {e.host ?? "—"}
                      {e.user ? ` · ${e.user}` : ""}
                    </td>
                    <td className="px-2 py-2 font-mono text-xs text-slate-300">{e.src_ip ?? "—"}</td>
                    <td className="max-w-md px-2 py-2 text-slate-200">{e.message}</td>
                    <td className="px-2 py-2 text-xs text-slate-500">{e.source_product}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <LiveAlertStrip />
    </div>
  );
}

function LiveAlertStrip() {
  const alerts = useLive((s) => s.alerts);
  if (alerts.length === 0) return null;
  return (
    <Card title="Live detections" subtitle="Alerts pushed by the detection engine">
      <ul className="space-y-2">
        {alerts.slice(0, 8).map((a) => (
          <li key={a.id} className="flex items-start justify-between gap-4 rounded-lg border border-sentinel-border/60 bg-white/[0.02] px-3 py-2">
            <div className="min-w-0">
              <span className="font-mono text-xs text-cyan-300">{a.rule_id}</span>
              <span className="ml-2 text-sm text-slate-200">{a.rule_title}</span>
              <div className="text-xs text-slate-400">entity {a.entity_key} · {timeAgo(a.time)}</div>
            </div>
            <Badge className="border-amber-500/40 bg-amber-500/15 text-amber-200">
              sev {a.severity_id}
            </Badge>
          </li>
        ))}
      </ul>
    </Card>
  );
}