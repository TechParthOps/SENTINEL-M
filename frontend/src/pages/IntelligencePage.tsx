import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Button, Card, Empty, Spinner, ErrorBox, Badge } from "../components/ui";
import { formatTime, timeAgo } from "../lib/format";

interface Indicator {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  reliability: string;
  status: "active" | "expired" | "future";
  valid_until: string | null;
  tags: string[];
  times_observed: number;
  last_seen: string | null;
}

interface Status {
  total: number;
  by_status: Record<string, number>;
  by_source: Record<string, number>;
  min_alert_confidence: number;
}

export default function IntelligencePage() {
  const user = useAuth((s) => s.user);
  const isAdmin = canAct(user?.role, "admin");
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [status, setStatus] = useState<Status | null>(null);
  const [query, setQuery] = useState({ ioc_type: "", status: "", search: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [lookup, setLookup] = useState<{ type: string; value: string; result: Indicator[] | null } | null>(null);

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "200" });
      if (query.ioc_type) params.set("ioc_type", query.ioc_type);
      if (query.status) params.set("status", query.status);
      if (query.search) params.set("search", query.search);
      const [list, st] = await Promise.all([
        api.get<{ indicators: Indicator[] }>(`/intel/indicators?${params}`),
        api.get<Status>("/intel/status"),
      ]);
      setIndicators(list.indicators);
      setStatus(st);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load intelligence");
    }
  }, [query]);

  useEffect(() => {
    load();
  }, [load]);

  async function reloadFeeds() {
    setBusy(true);
    try {
      await api.post("/intel/feeds/reload");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "reload failed");
    } finally {
      setBusy(false);
    }
  }

  async function runLookup() {
    if (!lookup) return;
    const value = lookup.value.trim();
    if (!value) return;
    try {
      const res = await api.get<{ matches: Indicator[] }>(
        `/intel/lookup?ioc_type=${lookup.type}&value=${encodeURIComponent(value)}`
      );
      setLookup({ type: lookup.type, value: lookup.value, result: res.matches });
    } catch (e) {
      setError(e instanceof Error ? e.message : "lookup failed");
    }
  }

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Threat Intelligence</h1>
          <p className="text-sm text-sentinel-muted">
            STIX 2.1 indicators from local feeds (`intel-feeds/`) — offline-first, provenance-tracked,
            indicator aging enforced. Feeds never auto-load from the network.
          </p>
        </div>
        {isAdmin && (
          <Button onClick={reloadFeeds} disabled={busy}>
            {busy ? "Reloading…" : "Reload feeds"}
          </Button>
        )}
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {status && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <Metric label="Indicators" value={status.total} hint={`${status.by_status.active ?? 0} active · ${status.by_status.expired ?? 0} expired`} />
          <Metric label="Feed sources" value={Object.keys(status.by_source).length} hint={Object.keys(status.by_source).join(", ") || "none"} />
          <Metric label="Alert threshold" value={status.min_alert_confidence} hint="indicators below this confidence are recorded but never alert" />
        </div>
      )}

      <Card title="IOC lookup" subtitle="Safe resolution against active, non-expired indicators">
        <div className="flex flex-wrap items-center gap-2">
          <select
            value={lookup?.type ?? "ipv4"}
            onChange={(e) => setLookup({ type: e.target.value, value: lookup?.value ?? "", result: null })}
            className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
          >
            {["ipv4", "domain", "url", "sha256", "sha1", "md5"].map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <input
            value={lookup?.value ?? ""}
            onChange={(e) => setLookup({ type: lookup?.type ?? "ipv4", value: e.target.value, result: null })}
            placeholder="indicator value…"
            className="min-w-64 flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 text-sm"
          />
          <Button variant="ghost" onClick={runLookup}>Look up</Button>
        </div>
        {Array.isArray(lookup?.result) && (
          <div className="mt-3 text-sm">
            {(lookup.result as Indicator[]).length === 0 ? (
              <p className="text-sentinel-muted">No active indicator matches this value.</p>
            ) : (
              <ul className="space-y-1">
                {(lookup.result as Indicator[]).map((m) => (
                  <li key={m.id} className="text-slate-300">
                    <span className="font-mono text-amber-200">{m.value}</span> — source {m.source}, confidence {m.confidence} ({m.reliability})
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </Card>

      <Card title={`Indicator registry (${indicators.length})`} subtitle="Newest imports first">
        <div className="mb-3 flex flex-wrap gap-2">
          <select value={query.ioc_type} onChange={(e) => setQuery({ ...query, ioc_type: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200">
            <option value="">all types</option>
            {["ipv4", "domain", "url", "sha256", "sha1", "md5", "email"].map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={query.status} onChange={(e) => setQuery({ ...query, status: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200">
            <option value="">any status</option>
            <option value="active">active</option>
            <option value="expired">expired</option>
            <option value="future">future</option>
          </select>
          <input value={query.search} onChange={(e) => setQuery({ ...query, search: e.target.value })} placeholder="search value…" className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 text-sm" />
        </div>
        {indicators.length === 0 ? (
          <Empty>No indicators loaded. Place STIX 2.1 bundles in `intel-feeds/` and reload.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wider text-sentinel-muted">
                  <th className="px-2 py-2">Type</th>
                  <th className="px-2 py-2">Value</th>
                  <th className="px-2 py-2">Source</th>
                  <th className="px-2 py-2">Conf.</th>
                  <th className="px-2 py-2">Status</th>
                  <th className="px-2 py-2">Observed</th>
                  <th className="px-2 py-2">Valid until</th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((i) => (
                  <tr key={i.id} className="border-t border-sentinel-border/40 hover:bg-cyan-500/[0.04]">
                    <td className="px-2 py-2 font-mono text-xs text-cyan-200">{i.type}</td>
                    <td className="max-w-md px-2 py-2 font-mono text-xs text-slate-200">{i.value}</td>
                    <td className="px-2 py-2 text-xs text-slate-400">{i.source}</td>
                    <td className="px-2 py-2 text-xs">
                      <span className={i.confidence >= 80 ? "text-red-300" : i.confidence >= 60 ? "text-amber-300" : "text-slate-400"}>
                        {i.confidence} ({i.reliability})
                      </span>
                    </td>
                    <td className="px-2 py-2">
                      <Badge className={i.status === "active" ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200" : "border-slate-500/40 bg-slate-600/20 text-slate-300"}>
                        {i.status}
                      </Badge>
                    </td>
                    <td className="px-2 py-2 text-xs text-slate-400">{i.times_observed}× {i.last_seen ? timeAgo(i.last_seen) : ""}</td>
                    <td className="px-2 py-2 text-xs text-slate-500">{i.valid_until ? formatTime(i.valid_until) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <p className="text-xs text-sentinel-muted">
        Indicators below confidence {status?.min_alert_confidence ?? 60} are recorded and observable in
        event enrichment but never generate alerts. Expired indicators never match — that is the
        indicator-aging control, not a filtering bug.
      </p>
    </div>
  );
}

function Metric({ label, value, hint }: { label: string; value: number; hint: string }) {
  return (
    <div className="rounded-xl border border-sentinel-border bg-sentinel-surface/80 p-4">
      <div className="text-xs uppercase tracking-wider text-sentinel-muted">{label}</div>
      <div className="mt-1 text-3xl font-bold text-cyan-300">{value}</div>
      <div className="mt-1 text-xs text-slate-400">{hint}</div>
    </div>
  );
}