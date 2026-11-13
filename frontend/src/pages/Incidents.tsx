import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Button, Card, Empty, Spinner, ErrorBox, Badge } from "../components/ui";
import { formatTime, jsonPretty, severityClass, severityLabel, statusClass, truncate } from "../lib/format";

interface IncidentRow {
  id: string;
  title: string;
  summary: string;
  category: string;
  severity_id: number;
  entity_keys: string[];
  attack_ids: string[];
  attack_chain: boolean;
  alert_ids: string[];
  timeline: { t: string; rule_id: string; rule_title: string; entity_key: string; severity_id: number; attack_ids: string[] }[];
  status: string;
  analyst_notes: string;
  first_seen: string;
  last_seen: string;
}

interface AlertDetail {
  id: string;
  time: string;
  rule_id: string;
  rule_title: string;
  severity_id: number;
  entity_key: string;
  attack_ids: string[];
  evidence_event_ids: string[];
  status: string;
  message: string;
}

export default function Incidents() {
  const user = useAuth((s) => s.user);
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<AlertDetail[]>([]);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ incidents: IncidentRow[] }>("/incidents?limit=100");
      setIncidents(res.incidents);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load incidents");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, [load]);

  useEffect(() => {
    if (!selected) return;
    api
      .get<{ analyst_notes: string; alerts: AlertDetail[] }>(`/incidents/${selected}`)
      .then((d) => {
        setAlerts(d.alerts);
        setNotes(d.analyst_notes ?? "");
      })
      .catch((e) => setError(e.message));
  }, [selected]);

  const current = incidents.find((i) => i.id === selected) ?? null;
  const canWork = canAct(user?.role, "analyst");

  async function updateIncident(status?: string) {
    if (!current) return;
    try {
      await api.patch(`/incidents/${current.id}`, { status, analyst_notes: notes });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "update failed");
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Incidents</h1>
        <p className="text-sm text-sentinel-muted">
          Correlated alert groups with evidence-backed timelines (NIST SP 800-61r3 workflow aligned)
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      <div className="grid gap-4 xl:grid-cols-[1fr_1.2fr]">
        <Card title={`Incident queue (${incidents.length})`} subtitle="Newest activity first">
          {incidents.length === 0 ? (
            <Empty>No incidents yet. Correlated alerts appear here automatically.</Empty>
          ) : (
            <ul className="space-y-2">
              {incidents.map((i) => (
                <li key={i.id}>
                  <button
                    onClick={() => setSelected(i.id)}
                    className={`w-full rounded-lg border p-3 text-left transition-colors ${
                      selected === i.id
                        ? "border-cyan-500/60 bg-cyan-500/10"
                        : "border-sentinel-border/70 bg-white/[0.02] hover:bg-white/[0.05]"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <Badge className={severityClass(i.severity_id)}>{severityLabel(i.severity_id)}</Badge>
                      {i.attack_chain && (
                        <Badge className="border-red-500/40 bg-red-500/15 text-red-200">chain</Badge>
                      )}
                      <span className="text-xs text-slate-400">{i.category.replace(/_/g, " ")}</span>
                      <span className={`ml-auto rounded-full border px-2 text-[11px] ${statusClass(i.status)}`}>
                        {i.status}
                      </span>
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-100">{i.title}</div>
                    <div className="mt-0.5 text-xs text-slate-400">
                      {i.alert_ids.length} alert(s) · techniques {i.attack_ids.join(", ") || "—"} ·{" "}
                      {formatTime(i.last_seen)}
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>

        {!current ? (
          <Card title="Incident detail">
            <Empty>Select an incident to inspect its evidence-backed timeline.</Empty>
          </Card>
        ) : (
          <div className="space-y-4">
            <Card
              title={current.title}
              subtitle={`${current.severity_id} · ${severityLabel(current.severity_id)} · entities: ${current.entity_keys.join(", ")}`}
            >
              <p className="mb-3 text-sm leading-relaxed text-slate-300">{current.summary}</p>

              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-sentinel-muted">
                Timeline (recorded evidence)
              </h3>
              <ol className="space-y-2 border-l border-sentinel-border pl-4">
                {current.timeline.map((t, idx) => (
                  <li key={idx} className="relative text-sm">
                    <span className="absolute -left-[21px] mt-1 h-2 w-2 rounded-full bg-cyan-400" />
                    <div className="font-mono text-xs text-slate-400">{formatTime(t.t)}</div>
                    <div className="text-slate-200">
                      {t.rule_title}{" "}
                      <span className="font-mono text-xs text-amber-200">{t.attack_ids.join(", ")}</span>
                    </div>
                  </li>
                ))}
              </ol>
            </Card>

            <Card title={`Supporting evidence (${alerts.length} alerts)`} subtitle="Each alert references ingested event IDs">
              {alerts.length === 0 ? (
                <Spinner label="Loading evidence…" />
              ) : (
                <div className="space-y-3">
                  {alerts.map((a) => (
                    <div key={a.id} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={severityClass(a.severity_id)}>{severityLabel(a.severity_id)}</Badge>
                        <span className="font-mono text-xs text-cyan-300">{a.rule_id}</span>
                        <span className="text-sm text-slate-200">{a.rule_title}</span>
                      </div>
                      <div className="mt-1 text-xs text-slate-400">
                        entity <span className="font-mono text-slate-300">{a.entity_key}</span> ·{" "}
                        {formatTime(a.time)} · status {a.status}
                      </div>
                      <p className="mt-1 text-sm text-slate-300">{truncate(a.message, 240)}</p>
                      <div className="mt-2">
                        <div className="text-[11px] uppercase tracking-wider text-sentinel-muted">
                          Evidence event IDs ({a.evidence_event_ids.length})
                        </div>
                        <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-slate-400">
                          {a.evidence_event_ids.slice(0, 8).map((eid) => (
                            <li key={eid}>{eid}</li>
                          ))}
                          {a.evidence_event_ids.length > 8 && (
                            <li>… +{a.evidence_event_ids.length - 8} more</li>
                          )}
                        </ul>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {canWork && (
              <Card title="Analyst workflow" subtitle="Notes and status transitions are audit-recorded">
                <textarea
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                  rows={4}
                  placeholder="Analyst notes — what was found, what was ruled out, next steps…"
                  className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg p-3 text-sm text-slate-200 outline-none focus:border-cyan-500/60"
                />
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button onClick={() => updateIncident("investigating")}>Save & investigate</Button>
                  <Button variant="ghost" onClick={() => updateIncident("contained")}>Contained</Button>
                  <Button variant="ghost" onClick={() => updateIncident("resolved")}>Resolved</Button>
                  <Button variant="ghost" onClick={() => updateIncident("closed")}>Closed</Button>
                </div>
              </Card>
            )}

            <details className="rounded-lg border border-sentinel-border bg-sentinel-surface/60 p-3">
              <summary className="cursor-pointer text-xs uppercase tracking-wider text-sentinel-muted">
                Raw incident record (JSON)
              </summary>
              <pre className="mt-2 overflow-x-auto text-[11px] text-slate-400">{jsonPretty(current)}</pre>
            </details>
          </div>
        )}
      </div>
    </div>
  );
}