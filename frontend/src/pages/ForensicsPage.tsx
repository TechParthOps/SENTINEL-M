import { useCallback, useEffect, useState } from "react";
import { api } from "../lib/api";
import { Badge, Button, Card, Empty, ErrorBox, Spinner } from "../components/ui";
import { formatTime } from "../lib/format";

interface Investigation {
  id: string;
  subject_type: string;
  subject_id: string;
  status: string;
  verdict: string;
  summary: string;
  created_at: string | null;
}

interface EvidenceItem {
  id: string;
  seq: number;
  kind: string;
  ref_id: string;
  content: string;
  sha256: string;
  prev_hash: string;
  collected_at: string | null;
}

interface EvidenceChain {
  investigation_id: string;
  chain_valid: boolean;
  count: number;
  evidence: EvidenceItem[];
}

interface MediaAnalysis {
  id: string;
  kind: string;
  verdict: string;
  filename?: string;
  created_at: string | null;
}

interface MalwareSample {
  id: string;
  sha256: string;
  filename: string;
  entropy: number;
  verdict: string;
  created_at: string | null;
}

function shortHash(h: string): string {
  return h.length > 16 ? `${h.slice(0, 16)}…` : h;
}

export default function ForensicsPage() {
  const [investigations, setInvestigations] = useState<Investigation[] | null>(null);
  const [chain, setChain] = useState<EvidenceChain | null>(null);
  const [media, setMedia] = useState<MediaAnalysis[] | null>(null);
  const [samples, setSamples] = useState<MalwareSample[] | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [inv, med, mal] = await Promise.all([
        api.get<{ investigations: Investigation[] }>("/agents/investigations?limit=50"),
        api.get<{ analyses: MediaAnalysis[] }>("/media/analyses?limit=25"),
        api.get<{ samples: MalwareSample[] }>("/malware/samples").catch(() => ({ samples: [] })),
      ]);
      setInvestigations(inv.investigations);
      setMedia(med.analyses);
      setSamples(mal.samples ?? []);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "failed to load forensic records");
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!selected) {
      setChain(null);
      return;
    }
    api.get<EvidenceChain>(`/agents/investigations/${selected}/evidence`)
      .then(setChain)
      .catch(() => setChain(null));
  }, [selected]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!investigations || !media || !samples) return <Spinner label="Loading forensic records…" />;

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Digital Forensics</h1>
          <p className="text-sm text-sentinel-muted">
            Evidence collected by autonomous investigations, plus stored analysis artifacts.
            Every record here comes from a real analysis run — bytes are never retained.
          </p>
        </div>
        <Button variant="ghost" onClick={load}>Refresh</Button>
      </header>

      <Card
        title="Evidence chain of custody"
        subtitle="SHA-256 hash chain per investigation — tamper-evident, verifiable on demand"
      >
        {investigations.length === 0 ? (
          <Empty>No investigations yet — start one from the Autonomous Agents page.</Empty>
        ) : (
          <>
            <div className="flex flex-wrap gap-2">
              {investigations.slice(0, 8).map((inv) => (
                <button
                  key={inv.id}
                  onClick={() => setSelected(selected === inv.id ? null : inv.id)}
                  className={`rounded-lg border px-2 py-1 text-xs ${
                    selected === inv.id ? "border-cyan-500/60 text-cyan-200" : "border-sentinel-border text-slate-300 hover:bg-white/5"
                  }`}
                >
                  {inv.subject_type}/{shortHash(inv.subject_id)} · {inv.verdict}
                </button>
              ))}
            </div>
            {selected && chain && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center gap-3 text-sm">
                  <Badge className={chain.chain_valid
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                    : "border-red-500/40 bg-red-500/15 text-red-200"}>
                    {chain.chain_valid ? "chain valid" : "chain BROKEN"}
                  </Badge>
                  <span className="text-slate-400">{chain.count} evidence items</span>
                </div>
                {chain.evidence.map((e) => (
                  <div key={e.id} className="rounded-lg border border-sentinel-border/50 p-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-cyan-200">#{e.seq} {e.kind}</span>
                      <span className="text-slate-500">{e.collected_at ? formatTime(e.collected_at) : "-"}</span>
                    </div>
                    <p className="mt-1 text-slate-300">{e.content}</p>
                    <div className="mt-1 flex flex-wrap gap-x-4 font-mono text-[10px] text-slate-500">
                      <span title={e.sha256}>sha256 {shortHash(e.sha256)}</span>
                      <span title={e.prev_hash || "(genesis)"}>prev {e.prev_hash ? shortHash(e.prev_hash) : "genesis"}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Multimodal analyses" subtitle="Image / audio / video / document / QR results (no bytes stored)">
          {media.length === 0 ? (
            <Empty>No media analyses yet.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="text-left text-sentinel-muted">
                    <th className="px-2 py-1">Kind</th>
                    <th className="px-2 py-1">File</th>
                    <th className="px-2 py-1">Verdict</th>
                    <th className="px-2 py-1">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {media.map((m) => (
                    <tr key={m.id} className="border-t border-sentinel-border/40">
                      <td className="px-2 py-1 text-cyan-200">{m.kind}</td>
                      <td className="px-2 py-1 text-slate-300">{m.filename ?? "-"}</td>
                      <td className="px-2 py-1 text-slate-300">{m.verdict}</td>
                      <td className="px-2 py-1 text-slate-500">{m.created_at ? formatTime(m.created_at) : "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Malware static analysis" subtitle="Hash-only evidence: content is analyzed, never retained">
          {samples.length === 0 ? (
            <Empty>No malware analyses yet.</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="text-left text-sentinel-muted">
                    <th className="px-2 py-1">File</th>
                    <th className="px-2 py-1">SHA-256</th>
                    <th className="px-2 py-1">Entropy</th>
                    <th className="px-2 py-1">Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {samples.map((s) => (
                    <tr key={s.id} className="border-t border-sentinel-border/40">
                      <td className="px-2 py-1 text-slate-300">{s.filename}</td>
                      <td className="px-2 py-1 font-mono text-slate-500" title={s.sha256}>{shortHash(s.sha256)}</td>
                      <td className="px-2 py-1 text-slate-300">{s.entropy?.toFixed(2) ?? "-"}</td>
                      <td className="px-2 py-1 text-slate-300">{s.verdict}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}