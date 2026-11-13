import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Card, Spinner, ErrorBox, Badge } from "../components/ui";

interface Capability {
  name: string;
  status: "implemented" | "partial" | "planned" | "blocked";
}

interface Phase {
  phase: number;
  status: "implemented" | "planned";
  title: string;
  capabilities: Capability[];
}

export default function CoveragePage() {
  const [phases, setPhases] = useState<Phase[]>([]);
  const [runtime, setRuntime] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .get<{ phases: Phase[]; runtime: Record<string, unknown> }>("/coverage")
      .then((res) => {
        setPhases(res.phases);
        setRuntime(res.runtime);
      })
      .catch((e) => setError(e.message));
  }, []);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (phases.length === 0) return <Spinner />;

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">Capability Coverage</h1>
        <p className="text-sm text-sentinel-muted">
          The authoritative status of every planned capability — rendered from the same data as{" "}
          <code className="text-cyan-300">research/THREAT_COVERAGE_MATRIX.md</code>. Nothing here is
          aspirational marketing copy.
        </p>
      </header>

      {runtime && (
        <Card title="Runtime state" subtitle="What is actually running right now">
          <pre className="overflow-x-auto text-xs text-slate-400">{JSON.stringify(runtime, null, 2)}</pre>
        </Card>
      )}

      <div className="space-y-4">
        {phases.map((p) => (
          <Card
            key={p.phase}
            title={`Phase ${p.phase} — ${p.title}`}
            right={
              <Badge
                className={
                  p.status === "implemented"
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
                    : "border-slate-500/40 bg-slate-600/20 text-slate-300"
                }
              >
                {p.status}
              </Badge>
            }
          >
            <ul className="grid gap-2 sm:grid-cols-2">
              {p.capabilities.map((c) => (
                <li key={c.name} className="flex items-start gap-2 text-sm">
                  <span
                    className={
                      c.status === "implemented"
                        ? "mt-1 h-2 w-2 shrink-0 rounded-full bg-emerald-400"
                        : "mt-1 h-2 w-2 shrink-0 rounded-full bg-slate-500"
                    }
                  />
                  <span className="text-slate-300">{c.name}</span>
                </li>
              ))}
            </ul>
          </Card>
        ))}
      </div>
    </div>
  );
}