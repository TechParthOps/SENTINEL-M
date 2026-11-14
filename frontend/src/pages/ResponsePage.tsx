import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Table } from "../components/ui";
import { timeAgo } from "../lib/format";

interface Policy {
  allowlist: Record<string, { autonomy_level: number; reversible: boolean; description: string }>;
  auto_execute_level: number;
  response_enabled: boolean;
  rule: string;
}

interface Action {
  id: string;
  action_type: string;
  target_type: string;
  target: string;
  reason: string;
  status: string;
  dry_run: boolean;
  requested_by: string;
  approved_by: string | null;
  verification?: { verified?: boolean };
  created_at: string | null;
}

const statusClass: Record<string, string> = {
  verified: "border-emerald-500/40 bg-emerald-500/15 text-emerald-200",
  executed: "border-cyan-500/40 bg-cyan-500/15 text-cyan-200",
  approved: "border-cyan-500/40 bg-cyan-500/15 text-cyan-200",
  dry_run: "border-sky-500/40 bg-sky-500/15 text-sky-200",
  requested: "border-amber-500/40 bg-amber-500/15 text-amber-200",
  denied: "border-slate-500/40 bg-slate-500/15 text-slate-300",
  failed: "border-red-500/40 bg-red-500/15 text-red-200",
  rolled_back: "border-slate-500/40 bg-slate-500/15 text-slate-300",
};

export default function ResponsePage() {
  const user = useAuth((s) => s.user);
  const isAdmin = canAct(user?.role, "admin");
  const isAnalyst = canAct(user?.role, "analyst");
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [actions, setActions] = useState<Action[]>([]);
  const [denylist, setDenylist] = useState<{ entries: { ip: string; reason: string }[] } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [type, setType] = useState("asset_isolate");
  const [targetType, setTargetType] = useState("asset");
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");
  const [dryRun, setDryRun] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [p, a, d] = await Promise.all([
        api.get<Policy>("/response/policy"),
        api.get<{ actions: Action[] }>("/response/actions?limit=50"),
        api.get<{ entries: { ip: string; reason: string }[] }>("/response/denylist"),
      ]);
      setPolicy(p);
      setActions(a.actions);
      setDenylist(d);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load response data");
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 6000);
    return () => clearInterval(t);
  }, [load]);

  async function submit() {
    if (!target.trim() || !reason.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.post("/response/actions", {
        action_type: type, target_type: targetType, target: target.trim(),
        reason: reason.trim(), dry_run: dryRun,
      });
      setTarget("");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "request failed");
    } finally {
      setBusy(false);
    }
  }

  async function doAction(id: string, verb: "approve" | "deny" | "execute" | "rollback") {
    setError(null);
    try {
      await api.post(`/response/actions/${id}/${verb}`, verb === "deny" ? { reason: "denied in UI" } : {});
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : `${verb} failed`);
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Response Playbooks</h1>
        <p className="text-sm text-sentinel-muted">
          Policy-gated response: a strict action allowlist with autonomy levels (L0 approval-always,
          L1 dry-run-auto, L2 reversible auto-execution on non-critical assets). Every executed
          action is verified by re-reading the target state, and reversible where possible.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {policy && (
        <Card
          title="Active policy"
          subtitle={policy.rule}
          right={
            <Badge className={policy.response_enabled
              ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
              : "border-red-500/40 bg-red-500/15 text-red-200"}>
              {policy.response_enabled ? "response enabled" : "EMERGENCY STOP"}
            </Badge>
          }
        >
          <div className="overflow-x-auto">
            <Table
              head={["Action", "Level", "Reversible", "Effect"]}
              rows={Object.entries(policy.allowlist).map(([k, v]) => [
                <span className="font-mono text-xs text-cyan-300">{k}</span>,
                <span className="text-slate-300">L{v.autonomy_level}</span>,
                <span className="text-slate-300">{v.reversible ? "yes" : "no"}</span>,
                <span className="text-xs text-slate-400">{v.description}</span>,
              ])}
            />
          </div>
        </Card>
      )}

      {isAnalyst && (
        <Card title="Request a response action" subtitle="L0/L1 actions require admin approval before execution">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <select value={type} onChange={(e) => setType(e.target.value)}
                      className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200">
                {policy && Object.keys(policy.allowlist).map((k) => (
                  <option key={k} value={k}>{k} (L{policy.allowlist[k].autonomy_level})</option>
                ))}
              </select>
              <select value={targetType} onChange={(e) => setTargetType(e.target.value)}
                      className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200">
                <option value="asset">asset</option>
                <option value="ip">ip</option>
                <option value="alert">alert</option>
                <option value="incident">incident</option>
              </select>
              <input value={target} onChange={(e) => setTarget(e.target.value)}
                     placeholder="target (hostname / IP / alert ID)…"
                     className="min-w-[220px] flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 font-mono text-sm text-slate-200" />
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
                dry-run
              </label>
            </div>
            <input value={reason} onChange={(e) => setReason(e.target.value)}
                   placeholder="reason (required, audit-recorded)…"
                   className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 text-sm text-slate-200" />
            <Button onClick={submit} disabled={busy || !target.trim() || !reason.trim()}>
              {busy ? "Submitting…" : dryRun ? "Simulate (dry-run)" : "Request action"}
            </Button>
          </div>
        </Card>
      )}

      <Card title="Response actions" subtitle="Newest 50 (auto-refreshing)">
        {actions.length === 0 ? (
          <Empty>No response actions yet.</Empty>
        ) : (
          <div className="space-y-2">
            {actions.map((a) => (
              <div key={a.id} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className={statusClass[a.status] ?? ""}>{a.status}</Badge>
                  <span className="font-mono text-xs text-cyan-300">{a.action_type}</span>
                  <span className="text-sm text-slate-300">
                    {a.target_type}:{a.target}
                  </span>
                  {a.dry_run && <span className="text-[11px] text-sky-300">dry-run</span>}
                  {a.verification?.verified && <span className="text-[11px] text-emerald-300">verified</span>}
                  <span className="ml-auto text-xs text-slate-500">{timeAgo(a.created_at ?? "")}</span>
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  by {a.requested_by}
                  {a.approved_by ? ` · approved by ${a.approved_by}` : ""} · {a.reason}
                </div>
                {isAdmin && (a.status === "requested" || a.status === "approved") && (
                  <div className="mt-2 flex gap-2">
                    {a.status === "requested" && (
                      <>
                        <Button variant="ghost" onClick={() => doAction(a.id, "approve")}>Approve</Button>
                        <Button variant="danger" onClick={() => doAction(a.id, "deny")}>Deny</Button>
                      </>
                    )}
                    {a.status === "approved" && (
                      <Button onClick={() => doAction(a.id, "execute")}>Execute</Button>
                    )}
                  </div>
                )}
                {isAdmin && (a.status === "executed" || a.status === "verified") && (
                  <div className="mt-2">
                    <Button variant="ghost" onClick={() => doAction(a.id, "rollback")}>Rollback</Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>

      {denylist && denylist.entries.length > 0 && (
        <Card title="Response denylist" subtitle="Edge-integration feed (consumers poll this list)">
          <Table
            head={["IP", "Reason"]}
            rows={denylist.entries.map((e) => [
              <span className="font-mono text-xs text-cyan-200">{e.ip}</span>,
              <span className="text-slate-300">{e.reason}</span>,
            ])}
          />
        </Card>
      )}
    </div>
  );
}
