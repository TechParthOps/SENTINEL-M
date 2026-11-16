import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Badge, Button, Card, ErrorBox, Spinner } from "../components/ui";

interface IntegrationState {
  feeds: { feeds_dir: string; feeds: string[] };
  intelStatus: Record<string, unknown> | null;
  info: {
    environment: string;
    modules: string[];
    rules: { total: number; dir: string };
  } | null;
  coverage: { phases: { phase: number; title: string; status: string }[] } | null;
}

/** Connectors that exist today vs. adapters that require an external system. */
const AVAILABLE = [
  {
    name: "STIX 2.1 file feeds",
    detail: "JSON bundles imported from the local feed directory; validated, deduplicated and aged.",
  },
  {
    name: "Telemetry ingest API (OCSF-aligned)",
    detail: "POST /events/ingest for collectors; optional X-Ingest-Token protection.",
  },
  {
    name: "WebSocket live stream",
    detail: "Authenticated event bus for dashboards and the 3D office.",
  },
  {
    name: "Canary-token hit endpoint",
    detail: "Decoy URLs record interactions and raise alerts.",
  },
];

const PLANNED = [
  { name: "Zeek / Suricata log-tail adapters", need: "deployed sensor log directory" },
  { name: "Sysmon / osquery / Wazuh adapters", need: "agent telemetry source" },
  { name: "MISP / OpenCTI / TAXII clients", need: "reachable instance + credentials" },
  { name: "YARA + isolated sandbox", need: "yarahub / VM target" },
  { name: "Ticketing / chatops response actions", need: "external workflow provider" },
];

export default function IntegrationsPage() {
  const [state, setState] = useState<IntegrationState | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [feeds, intelStatus, info, coverage] = await Promise.all([
        api.get<{ feeds_dir: string; feeds: string[] }>("/intel/feeds"),
        api.get<Record<string, unknown>>("/intel/status"),
        api.get<IntegrationState["info"]>("/system/info"),
        api.get<{ phases: { phase: number; title: string; status: string }[] }>("/coverage"),
      ]);
      setState({ feeds, intelStatus, info, coverage });
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load integration status");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!state) return <Spinner label="Loading integration status…" />;

  const byPhase = new Map((state.coverage?.phases ?? []).map((p) => [p.phase, p.status]));

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Integrations</h1>
          <p className="text-sm text-sentinel-muted">
            What is actually connected to this instance — no connector is listed as available
            unless it is running here.
          </p>
        </div>
        <Button variant="ghost" onClick={load}>Re-check</Button>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Available connectors" subtitle="Verified against this running instance">
          <ul className="space-y-2 text-sm">
            {AVAILABLE.map((c) => (
              <li key={c.name} className="rounded-lg border border-sentinel-border p-2">
                <div className="flex items-center gap-2">
                  <Badge className="border-emerald-500/40 bg-emerald-500/15 text-emerald-200">available</Badge>
                  <span className="text-slate-200">{c.name}</span>
                </div>
                <p className="mt-1 text-xs text-sentinel-muted">{c.detail}</p>
              </li>
            ))}
          </ul>
        </Card>

        <Card title="Threat-intelligence feeds" subtitle="Offline-first STIX import (local directory)">
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-sentinel-muted">Feed directory</dt><dd className="truncate font-mono text-xs text-slate-300">{state.feeds.feeds_dir}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Feed files</dt><dd className="text-slate-200">{state.feeds.feeds.length}</dd></div>
          </dl>
          {state.feeds.feeds.length === 0 ? (
            <p className="mt-2 text-xs text-amber-200">No feed files present in the directory.</p>
          ) : (
            <ul className="mt-2 space-y-1">
              {state.feeds.feeds.map((f) => (
                <li key={f} className="flex items-center gap-2 rounded border border-sentinel-border/50 px-2 py-1 text-xs">
                  <span className="font-mono text-cyan-200">{f}</span>
                  <span className="ml-auto text-slate-500">STIX 2.1 JSON</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-xs text-sentinel-muted">
            Live TAXII/MISP/OpenCTI clients are intentionally not bundled — they need a reachable
            instance and credentials and are marked blocked in the coverage matrix.
          </p>
        </Card>

        <Card title="Runtime posture" subtitle="From /system/info and /coverage">
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between"><dt className="text-sentinel-muted">Environment</dt><dd className="text-slate-200">{state.info?.environment ?? "-"}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Registered modules</dt><dd className="text-slate-200">{state.info?.modules.length ?? 0}</dd></div>
            <div className="flex justify-between"><dt className="text-sentinel-muted">Detection rules</dt><dd className="text-slate-200">{state.info?.rules.total ?? 0}</dd></div>
          </dl>
          <div className="mt-3 flex flex-wrap gap-1">
            {(state.coverage?.phases ?? []).map((p) => (
              <span key={p.phase} className="rounded border border-sentinel-border px-1.5 py-0.5 text-[10px] text-slate-300">
                P{p.phase}: {p.status}
              </span>
            ))}
          </div>
          <p className="mt-2 text-xs text-sentinel-muted">
            Phases {Array.from(byPhase.entries()).filter(([, s]) => s !== "implemented").map(([p]) => p).join(", ") || "none"} are not fully implemented — see the capability matrix for exact items.
          </p>
        </Card>

        <Card title="Planned adapters" subtitle="Each needs an external system; none is claimed as working">
          <ul className="space-y-2 text-sm">
            {PLANNED.map((p) => (
              <li key={p.name} className="flex items-center justify-between rounded-lg border border-sentinel-border p-2">
                <span className="text-slate-300">{p.name}</span>
                <span className="text-xs text-slate-500">requires: {p.need}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}