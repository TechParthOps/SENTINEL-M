import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Card, Empty, Spinner, ErrorBox, Badge } from "../components/ui";
import { severityClass, severityLabel } from "../lib/format";

interface Rule {
  id: string;
  title: string;
  type: string;
  class: string;
  severity_id: number;
  category: string;
  attack_ids: string[];
  attack_tactics: string[];
  status: string;
  source: string;
  notes: string;
  source_file: string;
  window_seconds: number;
  min_count: number;
  distinct_field: string;
  cooldown_seconds: number;
  signature_scope: string | null;
}

export default function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ total: number; rules: Rule[] }>("/rules");
      setRules(res.rules);
      setTotal(res.total);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load rules");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Detection Rules</h1>
        <p className="text-sm text-sentinel-muted">
          Deterministic, version-controlled JSON rules loaded from <code className="text-cyan-300">detection-rules/</code>.
          Rules are never auto-modified by AI (Part 15).
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}
      {total === 0 && !error && <Spinner />}

      <div className="grid gap-3 lg:grid-cols-2">
        {rules.map((r) => (
          <Card key={r.id} title={r.title} subtitle={`${r.id} · ${r.source_file}`}>
            <div className="flex flex-wrap items-center gap-2">
              <Badge className={severityClass(r.severity_id)}>
                {severityLabel(r.severity_id)} · {r.severity_id}
              </Badge>
              <Badge className="border-cyan-500/40 bg-cyan-500/15 text-cyan-200">{r.type}</Badge>
              <Badge className="border-slate-500/40 bg-slate-600/20 text-slate-300">{r.class || "any class"}</Badge>
              <Badge className="border-emerald-500/40 bg-emerald-500/15 text-emerald-200">{r.status}</Badge>
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-400">
              <div>
                <dt className="text-sentinel-muted">ATT&CK techniques</dt>
                <dd className="font-mono text-amber-200">{r.attack_ids.join(", ")}</dd>
              </div>
              <div>
                <dt className="text-sentinel-muted">Tactics</dt>
                <dd>{r.attack_tactics.join(", ") || "—"}</dd>
              </div>
              <div>
                <dt className="text-sentinel-muted">Category</dt>
                <dd>{r.category}</dd>
              </div>
              <div>
                <dt className="text-sentinel-muted">Trigger</dt>
                <dd>
                  {r.type === "threshold"
                    ? `${r.min_count}${r.distinct_field ? ` distinct ${r.distinct_field}` : ""} in ${r.window_seconds}s`
                    : `pattern (sig: ${r.signature_scope ?? "n/a"})`}
                </dd>
              </div>
              <div>
                <dt className="text-sentinel-muted">Cooldown</dt>
                <dd>{r.cooldown_seconds}s</dd>
              </div>
              <div>
                <dt className="text-sentinel-muted">Source</dt>
                <dd className="truncate">{r.source}</dd>
              </div>
            </dl>
            {r.notes && <p className="mt-3 border-t border-sentinel-border/60 pt-2 text-xs italic text-slate-400">{r.notes}</p>}
          </Card>
        ))}
      </div>

      {rules.length === 0 && <Empty>No rules loaded.</Empty>}
    </div>
  );
}