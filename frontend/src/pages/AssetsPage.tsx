import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, Spinner, ErrorBox, Table } from "../components/ui";
import { formatTime } from "../lib/format";

interface AssetRow {
  id: number;
  hostname: string;
  display_name: string;
  asset_type: string;
  ip_address: string | null;
  os: string;
  owner: string;
  criticality: number;
  auto_registered: boolean;
  sample: boolean;
  last_seen: string | null;
}

export default function AssetsPage() {
  const user = useAuth((s) => s.user);
  const [assets, setAssets] = useState<AssetRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ hostname: "", display_name: "", asset_type: "server", ip_address: "", criticality: 3 });

  const load = async () => {
    try {
      const res = await api.get<{ assets: AssetRow[] }>("/assets?limit=500");
      setAssets(res.assets);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load assets");
    }
  };

  useEffect(() => {
    load();
  }, []);

  async function createAsset() {
    setError(null);
    try {
      await api.post("/assets", form);
      setCreating(false);
      setForm({ hostname: "", display_name: "", asset_type: "server", ip_address: "", criticality: 3 });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
    }
  }

  const canManage = canAct(user?.role, "analyst");

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Assets and Infrastructure</h1>
          <p className="text-sm text-sentinel-muted">
            Inventory is built from manual registration and telemetry auto-discovery. Sample entries are
            labeled explicitly.
          </p>
        </div>
        {canManage && <Button onClick={() => setCreating((v) => !v)}>{creating ? "Cancel" : "Register asset"}</Button>}
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {creating && (
        <Card title="Register asset" subtitle="Assets you declare are never fabricated from telemetry">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            <input placeholder="hostname" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
            <input placeholder="display name" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
            <select value={form.asset_type} onChange={(e) => setForm({ ...form, asset_type: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm">
              {["server", "workstation", "database", "firewall", "cloud_workload", "iot", "domain_controller", "unknown"].map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
            <input placeholder="ip address" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} className="rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
            <div className="flex gap-2">
              <input type="number" min={1} max={5} value={form.criticality} onChange={(e) => setForm({ ...form, criticality: Number(e.target.value) })} className="w-20 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-2 text-sm" />
              <Button onClick={createAsset} disabled={!form.hostname}>Create</Button>
            </div>
          </div>
        </Card>
      )}

      <Card title="Inventory" subtitle={`${assets.length} tracked assets`}>
        {assets.length === 0 ? (
          <Empty>No assets registered. Telemetry will auto-register hosts as events arrive.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["Hostname", "Type", "IP", "Criticality", "Source", "Last seen", "Notes"]}
              rows={assets.map((a) => [
                <span className="font-mono text-xs text-cyan-200">{a.hostname}</span>,
                <span className="text-slate-300">{a.asset_type}</span>,
                <span className="font-mono text-xs text-slate-400">{a.ip_address ?? "—"}</span>,
                <Badge className={a.criticality >= 4 ? "border-red-500/40 bg-red-500/15 text-red-200" : "border-slate-500/40 bg-slate-600/20 text-slate-300"}>
                  C{a.criticality}
                </Badge>,
                <span className="text-xs text-slate-400">
                  {a.auto_registered ? <span className="text-cyan-300">auto-registered</span> : "manual"}
                  {a.sample && <span className="ml-2 text-slate-500">sample inventory</span>}
                </span>,
                <span className="font-mono text-xs text-slate-400">{formatTime(a.last_seen)}</span>,
              ])}
            />
          </div>
        )}
      </Card>
    </div>
  );
}