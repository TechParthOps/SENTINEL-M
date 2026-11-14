import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Table } from "../components/ui";
import { timeAgo } from "../lib/format";

interface Pot {
  id: string;
  name: string;
  kind: string;
  port: number;
  status: string;
  decoy_identity: string;
  canary_path: string;
  interactions_count: number;
  created_by: string;
  created_at: string | null;
}

interface Interaction {
  id: string;
  time: string | null;
  source_ip: string;
  kind: string;
  detail: Record<string, unknown>;
}

export default function DeceptionPage() {
  const user = useAuth((s) => s.user);
  const isAdmin = canAct(user?.role, "admin");
  const [pots, setPots] = useState<Pot[]>([]);
  const [selected, setSelected] = useState<{ pot: Pot; interactions: Interaction[] } | null>(null);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("tcp_banner");
  const [port, setPort] = useState("15222");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ pots: Pot[] }>("/deception/pots");
      setPots(res.pots);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load honeypots");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 6000);
    return () => clearInterval(t);
  }, [load]);

  async function open(pot: Pot) {
    try {
      const res = await api.get<{ interactions: Interaction[] }>(
        `/deception/pots/${pot.id}/interactions`);
      setSelected({ pot, interactions: res.interactions });
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load interactions");
    }
  }

  async function create() {
    if (!name.trim()) return;
    setError(null);
    try {
      await api.post("/deception/pots", { name: name.trim(), kind, port: Number(port) || 0 });
      setName("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "create failed");
    }
  }

  async function lifecycle(pot: Pot, verb: "start" | "stop") {
    setError(null);
    try {
      await api.post(`/deception/pots/${pot.id}/${verb}`);
      await load();
      await open({ ...pot, status: verb === "start" ? "running" : "stopped" });
    } catch (e) {
      setError(e instanceof Error ? e.message : `${verb} failed`);
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Deception Lab</h1>
        <p className="text-sm text-sentinel-muted">
          Isolated deception assets: TCP decoy services and canary tokens. Listeners bind to
          the loopback interface by default, use unprivileged ports only, and their decoy
          credentials are randomly generated — never drawn from the real identity inventory.
          Every interaction raises a real DECEPTION-HP-001 alert.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {isAdmin && (
        <Card title="Create a deception asset" subtitle="Admin only · loopback listener · unprivileged port">
          <div className="flex flex-wrap items-center gap-3">
            <input value={name} onChange={(e) => setName(e.target.value)}
                   placeholder="name (e.g. hp-legacy-ssh)"
                   className="min-w-[200px] flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 text-sm text-slate-200" />
            <select value={kind} onChange={(e) => setKind(e.target.value)}
                    className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200">
              <option value="tcp_banner">tcp_banner (decoy SSH-style service)</option>
              <option value="canary_token">canary_token (URL token)</option>
            </select>
            {kind === "tcp_banner" && (
              <input value={port} onChange={(e) => setPort(e.target.value)}
                     placeholder="port 1024–65535"
                     className="w-28 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 font-mono text-sm text-slate-200" />
            )}
            <Button onClick={create} disabled={!name.trim()}>Create</Button>
          </div>
        </Card>
      )}

      <Card title="Deception assets" subtitle="Newest first (auto-refreshing)">
        {pots.length === 0 ? (
          <Empty>No honeypots yet{isAdmin ? "" : " (admin role required to create)"}.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["Name", "Kind", "Port", "Status", "Interactions", ""]}
              rows={pots.map((p) => [
                <button onClick={() => open(p)}
                        className="font-mono text-xs text-cyan-300 underline hover:text-cyan-200">
                  {p.name}
                </button>,
                <span className="text-slate-300">{p.kind}</span>,
                <span className="font-mono text-xs text-slate-400">{p.port || "—"}</span>,
                <Badge className={p.status === "running"
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                  : "border-slate-500/40 bg-slate-500/15 text-slate-300"}>
                  {p.status}
                </Badge>,
                <span className="font-mono text-xs text-slate-300">{p.interactions_count}</span>,
                isAdmin && (
                  <span className="flex gap-2">
                    {p.status !== "running" && p.kind !== "canary_token" && (
                      <Button variant="ghost" onClick={() => lifecycle(p, "start")}>Start</Button>
                    )}
                    {p.status === "running" && (
                      <Button variant="ghost" onClick={() => lifecycle(p, "stop")}>Stop</Button>
                    )}
                  </span>
                ),
              ])}
            />
          </div>
        )}
      </Card>

      {selected && (
        <Card
          title={`Interactions — ${selected.pot.name}`}
          subtitle={`${selected.pot.kind}${selected.pot.canary_path ? ` · canary path ${selected.pot.canary_path} (API-relative, public by design)` : ""}`}
        >
          {selected.interactions.length === 0 ? (
            <Empty>No interactions recorded. Interactions appear here in real time once triggered.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <Table
                head={["Time", "Source", "Kind", "Detail"]}
                rows={selected.interactions.map((i) => [
                  <span className="font-mono text-xs text-slate-400">{timeAgo(i.time ?? "")}</span>,
                  <span className="font-mono text-xs text-cyan-200">{i.source_ip}</span>,
                  <span className="text-slate-300">{i.kind}</span>,
                  <span className="max-w-[320px] truncate font-mono text-[11px] text-slate-400">
                    {JSON.stringify(i.detail)}
                  </span>,
                ])}
              />
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
