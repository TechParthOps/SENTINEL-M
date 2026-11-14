import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Spinner, Table } from "../components/ui";
import { timeAgo } from "../lib/format";

interface Task {
  id: string;
  seq: number;
  agent: string;
  description: string;
  status: string;
  output: Record<string, unknown>;
  error: string;
  evidence_count: number;
  duration_ms: number;
}

interface Investigation {
  id: string;
  subject_type: string;
  subject_id: string;
  status: string;
  verdict: string;
  summary: string;
  created_by: string;
  created_at: string | null;
  finished_at: string | null;
  tasks?: Task[];
}

interface EvidenceItem {
  id: string;
  seq: number;
  kind: string;
  ref_id: string;
  sha256: string;
  prev_hash: string;
}

const verdictClass: Record<string, string> = {
  malicious: "border-red-500/40 bg-red-500/15 text-red-200",
  suspicious: "border-amber-500/40 bg-amber-500/15 text-amber-200",
  benign: "border-emerald-500/40 bg-emerald-500/15 text-emerald-200",
  unknown: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

const statusClass: Record<string, string> = {
  completed: "border-emerald-500/40 bg-emerald-500/15 text-emerald-200",
  running: "border-cyan-500/40 bg-cyan-500/15 text-cyan-200",
  failed: "border-red-500/40 bg-red-500/15 text-red-200",
  queued: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

export default function AgentsPage() {
  const user = useAuth((s) => s.user);
  const canRun = canAct(user?.role, "analyst");
  const [list, setList] = useState<Investigation[]>([]);
  const [selected, setSelected] = useState<Investigation | null>(null);
  const [evidence, setEvidence] = useState<{ chain_valid: boolean; count: number; evidence: EvidenceItem[] } | null>(null);
  const [subjectType, setSubjectType] = useState<"alert" | "entity">("entity");
  const [subjectId, setSubjectId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ investigations: Investigation[] }>("/agents/investigations?limit=30");
      setList(res.investigations);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load investigations");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, [load]);

  async function open(id: string) {
    try {
      const [detail, ev] = await Promise.all([
        api.get<Investigation>(`/agents/investigations/${id}`),
        api.get<{ chain_valid: boolean; count: number; evidence: EvidenceItem[] }>(
          `/agents/investigations/${id}/evidence`),
      ]);
      setSelected(detail);
      setEvidence(ev);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load investigation");
    }
  }

  async function run() {
    if (!subjectId.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const created = await api.post<Investigation>("/agents/investigations", {
        subject_type: subjectType,
        subject_id: subjectId.trim(),
      });
      setSubjectId("");
      await load();
      await open(created.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "investigation failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Autonomous Agents</h1>
        <p className="text-sm text-sentinel-muted">
          Deterministic specialist agents (triage, asset context, intel check, related activity,
          synthesis) investigate alerts or entities and record evidence in a hash chain.
          Agents are <strong>read-only</strong> — no response actions are available to them.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {canRun && (
        <Card title="Start an investigation" subtitle="Investigate an alert ID or an entity (host/IP)">
          <div className="flex flex-wrap items-center gap-3">
            <select
              value={subjectType}
              onChange={(e) => setSubjectType(e.target.value as "alert" | "entity")}
              className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
            >
              <option value="alert">alert</option>
              <option value="entity">entity</option>
            </select>
            <input
              value={subjectId}
              onChange={(e) => setSubjectId(e.target.value)}
              placeholder={subjectType === "alert" ? "alert UUID…" : "hostname or IP…"}
              className="min-w-[240px] flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 font-mono text-sm text-slate-200"
            />
            <Button onClick={run} disabled={!subjectId.trim() || busy}>
              {busy ? "Investigating…" : "Investigate"}
            </Button>
          </div>
        </Card>
      )}

      <Card title="Investigations" subtitle="Newest 30 (auto-refreshing)">
        {list.length === 0 ? (
          <Empty>No investigations yet. Start one above{!canRun ? " (analyst role required)" : ""}.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["When", "Subject", "Status", "Verdict", "By"]}
              rows={list.map((inv) => [
                <span className="font-mono text-xs text-slate-400">{timeAgo(inv.created_at ?? "")}</span>,
                <button
                  onClick={() => open(inv.id)}
                  className="font-mono text-xs text-cyan-300 underline hover:text-cyan-200"
                >
                  {inv.subject_type}:{inv.subject_id.slice(0, 24)}
                </button>,
                <Badge className={statusClass[inv.status] ?? ""}>{inv.status}</Badge>,
                <Badge className={verdictClass[inv.verdict] ?? ""}>{inv.verdict}</Badge>,
                <span className="text-slate-400">{inv.created_by}</span>,
              ])}
            />
          </div>
        )}
      </Card>

      {selected && (
        <Card
          title={`Investigation ${selected.id.slice(0, 8)}…`}
          subtitle={`${selected.subject_type} ${selected.subject_id} · by ${selected.created_by}`}
          right={<Badge className={verdictClass[selected.verdict] ?? ""}>{selected.verdict}</Badge>}
        >
          <div className="space-y-4">
            <p className="text-sm text-slate-300">{selected.summary || "—"}</p>

            <div className="space-y-2">
              {(selected.tasks ?? []).map((t) => (
                <div key={t.id} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-cyan-300">{t.agent}</span>
                    <Badge className={statusClass[t.status] ?? ""}>{t.status}</Badge>
                    <span className="text-xs text-slate-500">{t.duration_ms} ms · {t.evidence_count} evidence</span>
                  </div>
                  <p className="text-xs text-slate-500">{t.description}</p>
                  {t.error && <p className="text-xs text-red-300">{t.error}</p>}
                  {Object.keys(t.output ?? {}).length > 0 && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-xs text-slate-400">output</summary>
                      <pre className="mt-1 max-h-48 overflow-auto rounded bg-black/40 p-2 text-[11px] text-slate-300">
                        {JSON.stringify(t.output, null, 2)}
                      </pre>
                    </details>
                  )}
                </div>
              ))}
            </div>

            {evidence && (
              <div>
                <div className="flex items-center gap-2 text-sm text-slate-300">
                  Evidence chain
                  <Badge className={evidence.chain_valid
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                    : "border-red-500/40 bg-red-500/15 text-red-200"}>
                    {evidence.chain_valid ? "chain valid" : "CHAIN BROKEN"}
                  </Badge>
                  <span className="text-xs text-slate-500">{evidence.count} records</span>
                </div>
                <div className="mt-2 overflow-x-auto">
                  <Table
                    head={["#", "Kind", "Ref", "SHA-256"]}
                    rows={evidence.evidence.map((e) => [
                      <span className="font-mono text-xs text-slate-400">{e.seq}</span>,
                      <span className="text-slate-300">{e.kind}</span>,
                      <span className="font-mono text-xs text-cyan-200">{e.ref_id.slice(0, 18)}…</span>,
                      <span className="font-mono text-[10px] text-slate-500">{e.sha256.slice(0, 24)}…</span>,
                    ])}
                  />
                </div>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
}
