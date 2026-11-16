import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { canAct, useAuth } from "../store/auth";
import { Badge, Button, Card, Empty, ErrorBox, Table } from "../components/ui";
import { timeAgo } from "../lib/format";

interface AnalysisResult {
  analysis_id: string | null;
  kind: string;
  status: string;
  filename: string;
  size: number;
  sha256: string;
  metadata?: Record<string, unknown>;
  stats?: Record<string, unknown>;
  qr?: { found: boolean; payload?: string; findings?: ResultFinding[] };
  findings: ResultFinding[];
  limitations: string[];
  error?: string;
  risk_score: number;
  verdict: string;
}

interface ResultFinding {
  category: string;
  confidence: number;
  evidence: string;
  note?: string;
}

interface AnalysisRow {
  id: string;
  kind: string;
  filename: string;
  sha256: string;
  size: number;
  mime: string;
  status: string;
  risk_score: number;
  verdict: string;
  created_at: string | null;
  submitted_by: string;
}

function verdictBadgeClass(v: string): string {
  if (v === "high_risk") return "border-red-500/40 bg-red-500/15 text-red-200";
  if (v === "indicators_only") return "border-amber-500/40 bg-amber-500/15 text-amber-200";
  if (v === "unsupported") return "border-slate-500/40 bg-slate-500/15 text-slate-300";
  return "border-emerald-500/40 bg-emerald-500/15 text-emerald-200";
}

export default function MultimodalPage() {
  const user = useAuth((s) => s.user);
  const canSubmit = canAct(user?.role, "analyst");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [rows, setRows] = useState<AnalysisRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await api.get<{ analyses: AnalysisRow[] }>("/media/analyses?limit=30");
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
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      // The File object is handed to FormData directly: the browser streams it
      // from disk as multipart/form-data. Nothing is read into JS memory and
      // there is no file-size limit.
      const form = new FormData();
      form.append("file", file, file.name);
      const res = await api.postForm<AnalysisResult>("/media/analyze", form);
      setResult(res);
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
        <h1 className="text-xl font-semibold text-slate-100">Multimodal Forensics</h1>
        <p className="text-sm text-sentinel-muted">
          Image metadata/EXIF + QR payload analysis, WAV audio statistics, OpenCV-decodable video
          frame statistics, PDF/OOXML structural scans. Deterministic + heuristic indicators with
          stated confidences — never authenticity or identity verdicts. Raw bytes are never stored.
        </p>
      </header>

      {error && <ErrorBox>{error}</ErrorBox>}

      {canSubmit && (
        <Card title="Submit media for analysis" subtitle="Any file size — streamed multipart upload, never buffered in the browser">
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="text-sm text-slate-300"
            />
            <Button onClick={submit} disabled={!file || busy}>
              {busy ? "Analyzing…" : "Analyze"}
            </Button>
          </div>
        </Card>
      )}

      {result && (
        <Card
          title={`Result — ${result.kind}`}
          subtitle={`${result.filename} · ${result.size.toLocaleString()} bytes · sha256 ${result.sha256.slice(0, 16)}…`}
          right={<Badge className={verdictBadgeClass(result.verdict)}>{result.verdict}</Badge>}
        >
          <div className="space-y-3 text-sm text-slate-300">
            {result.error && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-amber-200">
                {result.error}
              </div>
            )}
            {result.metadata && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500">Metadata</div>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-slate-300">
                  {Object.entries(result.metadata).map(([k, v]) => (
                    <li key={k}>{k}: {String(v)}</li>
                  ))}
                </ul>
              </div>
            )}
            {result.stats && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500">Statistics</div>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-slate-300">
                  {Object.entries(result.stats).map(([k, v]) => (
                    <li key={k}>{k}: {String(v)}</li>
                  ))}
                </ul>
              </div>
            )}
            {result.qr?.found && (
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500">QR payload</div>
                <p className="mt-1 break-all font-mono text-xs text-cyan-200">{result.qr.payload}</p>
                {result.qr.findings?.map((f, i) => (
                  <p key={i} className="text-xs text-amber-300">{f.category} ({f.confidence.toFixed(2)})</p>
                ))}
              </div>
            )}
            {result.findings.length === 0 && !result.qr?.found ? (
              <Empty>No threat indicators found by the available pipelines.</Empty>
            ) : (
              result.findings.length > 0 && (
                <div className="space-y-2">
                  {result.findings.map((f, i) => (
                    <div key={i} className="rounded-lg border border-sentinel-border/70 bg-white/[0.02] p-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge className={f.confidence >= 0.7 ? "border-red-500/40 bg-red-500/15 text-red-200" : "border-amber-500/40 bg-amber-500/15 text-amber-200"}>
                          {f.category}
                        </Badge>
                        <span className="text-xs text-slate-400">confidence {f.confidence.toFixed(2)}</span>
                      </div>
                      <p className="mt-1 text-sm text-slate-300">{f.evidence}</p>
                      {f.note && <p className="text-xs text-slate-500">{f.note}</p>}
                    </div>
                  ))}
                </div>
              )
            )}
            {result.limitations?.length > 0 && (
              <div className="rounded-lg border border-sentinel-border bg-white/[0.02] p-3">
                <div className="text-xs uppercase tracking-wide text-slate-500">Documented limitations</div>
                <ul className="mt-1 list-disc pl-4 text-xs text-slate-400">
                  {result.limitations.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
              </div>
            )}
          </div>
        </Card>
      )}

      <Card title="Stored analyses" subtitle="Newest 30 records (bytes never retained)">
        {rows.length === 0 ? (
          <Empty>No media analyses yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <Table
              head={["When", "Kind", "File", "Verdict", "Risk", "By"]}
              rows={rows.map((r) => [
                <span className="font-mono text-xs text-slate-400">{timeAgo(r.created_at ?? "")}</span>,
                <span className="text-slate-300">{r.kind}</span>,
                <span className="text-slate-300">{r.filename || "—"}</span>,
                <Badge className={verdictBadgeClass(r.verdict)}>{r.verdict}</Badge>,
                <span className="font-mono text-cyan-300">{r.risk_score.toFixed(2)}</span>,
                <span className="text-slate-400">{r.submitted_by}</span>,
              ])}
            />
          </div>
        )}
      </Card>
    </div>
  );
}
