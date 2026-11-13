/** Honest placeholder for capabilities not yet built — never a fake dashboard (ADR-008/010). */
import { Link } from "react-router-dom";
import { Card } from "../components/ui";

const PHASE_TITLES: Record<number, string> = {
  2: "Traditional Cyber Defense",
  3: "AI & Multimodal Security",
  4: "Autonomous Investigation",
  5: "Response & Deception",
  6: "3D Virtual Security Operations",
  7: "Enterprise Readiness",
};

const PHASE_CONTENTS: Record<number, string[]> = {
  2: [
    "Network telemetry adapters (Zeek, Suricata) with C2/beaconing detection",
    "Endpoint telemetry adapters (Sysmon, osquery, Wazuh) with process/registry detection",
    "Identity threat detection (password spray, impossible travel, MFA fatigue)",
    "Malware static analysis + YARA + isolated sandbox adapter",
    "Threat intelligence engine (MISP / OpenCTI / TAXII adapters, IOC aging)",
  ],
  3: [
    "Prompt-injection detection (direct + indirect), jailbreak heuristics, semantic classifiers",
    "Phishing / BEC text analysis and document forensics",
    "QR-code security (extract → normalize → risk explain, never auto-open)",
    "Image forensics and synthetic-image indicators",
    "Audio forensics (spectrogram/ASR/synthetic-speech classifiers with confidence + limitations)",
    "Video deepfake indicators and agent security monitoring",
  ],
  4: [
    "Multi-agent orchestrator with specialist investigation agents",
    "Structured tool schemas, permission boundaries, deterministic fallbacks",
    "Evidence collection with chain of custody",
    "Threat hunting queries and long-term timelines",
  ],
  5: [
    "Policy-authorized response engine (L0–L4 autonomy levels)",
    "Approval workflows, dry-run, rollback and post-action verification",
    "Isolated deception and honeypot subsystem with containment boundaries",
  ],
  6: [
    "Interactive 3D virtual security-operations office (React Three Fiber + drei)",
    "Live agent avatars bound to real agent execution state",
    "Digital twin, attack-path animation and historical incident replay",
    "2D fallback for machines without WebGL acceleration",
  ],
  7: [
    "Guided installer, update mechanism, backup/recovery",
    "MFA, hardening, SBOM, performance and regression suites",
  ],
};

export default function PlannedPage({ phase }: { phase: number }) {
  const title = PHASE_TITLES[phase] ?? `Phase ${phase}`;
  const items = PHASE_CONTENTS[phase] ?? [];

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
        <p className="text-sm text-sentinel-muted">
          This capability is <span className="text-amber-300">planned</span> and not yet built — it is
          scheduled for Phase {phase}. SENTINEL-M never displays simulated activity here.
        </p>
      </header>

      <Card title={`Planned scope (Phase ${phase})`} subtitle="From the approved development roadmap">
        <ul className="space-y-2">
          {items.map((item) => (
            <li key={item} className="flex items-start gap-2 text-sm">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-amber-400" />
              <span className="text-slate-300">{item}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title="Track progress">
        <p className="text-sm text-sentinel-muted">
          The engineering roadmap is public in the repository (CHANGELOG.md, research/THREAT_COVERAGE_MATRIX.md).
        </p>
        <Link to="/capabilities" className="mt-2 inline-block text-sm text-cyan-300 underline hover:text-cyan-200">
          View the capability coverage page →
        </Link>
      </Card>
    </div>
  );
}