import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Table } from "../components/ui";
import { timeAgo, truncate } from "../lib/format";

interface Finding {
  category: string;
  confidence: number;
  evidence: string;
  owasp_llm: string;
  atlas: string[];
}

interface AnalysisResult {
  analysis_id: string | null;
  context: string;
  size: number;
  text_sha256: string;
  findings: Finding[];
  categories: string[];
  risk_score: number;
  verdict: string;
  method: string;
}

interface AnalysisRow {
  id: string;
  kind: string;
  label: string;
  size: number;
  risk_score: number;
  verdict: string;
  categories: string[];
  created_at: string | null;
  submitted_by: string;
}

const CONTEXTS = ["prompt", "chat", "document", "web", "email", "rag", "llm_output"] as const;

function verdictBadgeClass(v: string): string {
  if (v === "high_risk") return "border-red-500/40 bg-red-500/15 text-red-200";
  if (v === "indicators_only") return "border-amber-500/40 bg-amber-500/15 text-amber-200";
  return "border-emerald-500/40 bg-emerald-500/15 text-emerald-200";
}

export default function AISecurityPage() {
  const user = useAuth((s) => s.user);
  const canSubmit = canAct(user?.role, "analyst");
  const [text, setText] = useState("");
  const [context, setContext] = useState<(typeof CONTEXTS)[number]>("prompt");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [rows, setRows] = useState<AnalysisRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ analyses: AnalysisRow[] }>("/aisec/analyses?limit=30");
      setRows(res.analyses);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load analyses");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function submit() {
    if (!text.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.post<AnalysisResult>("/aisec/analyze-text", { text, context, label: "UI" }));
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "analysis failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">AI &amp; LLM Security</h1>
        <p className="text-sm text-sentinel-muted">
          Deterministic, offline analysis of LLM-facing text: prompt injection (direct &amp; indirect),
          jailbreak/extraction patterns, RAG-poisoning indicators, data-disclosure indicators,
          tool-override instructions and phishing/BEC text markers. Confidences are heuristic
          evidence strengths — never intent verdicts.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {canSubmit && (
        <Card title="Analyze text" subtitle="Text stays in-process; only the analysis record is stored">
          <div className="space-y-3">
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={5}
              maxLength={200000}
              placeholder="Paste prompt, chat transcript, email or retrieved document text…"
              className="w-full rounded-lg border border-sentinel-border bg-sentinel-bg p-3 font-mono text-sm text-slate-200"
            />
            <div className="flex flex-wrap items-center gap-3">
              <select
                value={context}
                onChange={(e) => setContext(e.target.value as (typeof CONTEXTS)[number])}
                className="rounded-lg border border-sentinel-border bg-sentinel-bg px-2 py-1.5 text-sm text-slate-200"
              >
                {CONTEXTS.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              <Button onClick={submit} disabled={!text.trim() || busy}>
                {busy ? "Analyzing…" : "Analyze"}
              </Button>
              <span className="text-xs text-sentinel-muted">
                context controls which detectors apply (e.g. document → indirect injection)
              </span>
            </div>
          </div>
        </Card>
      )}

      {result && (
        <Card
          title="Analysis result"
          subtitle={`${result.context} · ${result.size} chars · method: ${result.method}`}
          right={<Badge className={verdictBadgeClass(result.verdict)}>{result.verdict}</Badge>}
        >
          <div className="space-y-3">
            <div className="text-sm text-slate-300">
              Risk score <span className="font-mono text-cyan-300">{result.risk_score.toFixed(2)}</span>
              {" "}· categories: {result.categories.length ? result.categories.join(", ") : "none"}
            </div>
            {result.findings.length === 0 ? (
              <Empty>No threat indicators found by the available detectors.</Empty>
            ) : (
              <div className="space-y-2">
                {result.findings.map((f, i) => (
                  <div key={i} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className={f.confidence >= 0.7 ? "border-red-500/40 bg-red-500/15 text-red-200" : "border-amber-500/40 bg-amber-500/15 text-amber-200"}>
                        {f.category}
                      </Badge>
                      <span className="text-xs text-slate-400">confidence {f.confidence.toFixed(2)}</span>
                      {f.owasp_llm && <span className="text-xs text-slate-500">OWASP {f.owasp_llm}</span>}
                      {f.atlas.length > 0 && <span className="text-xs text-slate-500">ATLAS {f.atlas.join(", ")}</span>}
                    </div>
                    <p className="mt-1 break-all text-sm text-slate-300">“{truncate(f.evidence, 220)}”</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>
      )}

      <Card title="Stored analyses" subtitle="Newest 30 records (text itself is not retained)">
        {rows.length === 0 ? (
          <Empty>No AI-security analyses yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["When", "Context", "Label", "Verdict", "Risk", "Categories"]}
              rows={rows.map((r) => [
                <span className="font-mono text-xs text-slate-400">{timeAgo(r.created_at ?? "")}</span>,
                <span className="text-slate-300">{r.kind}</span>,
                <span className="text-slate-400">{r.label || "—"}</span>,
                <Badge className={verdictBadgeClass(r.verdict)}>{r.verdict}</Badge>,
                <span className="font-mono text-cyan-300">{r.risk_score.toFixed(2)}</span>,
                <span className="text-xs text-slate-400">{r.categories.join(", ") || "—"}</span>,
              ])}
            />
          </div>
        )}
      </Card>
    </div>
  );
}
