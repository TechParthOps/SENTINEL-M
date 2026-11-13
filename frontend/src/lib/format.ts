/** Pure formatting helpers shared across pages. */

export const SEVERITY_LABELS: Record<number, string> = {
  0: "Unknown",
  1: "Informational",
  2: "Low",
  3: "Medium",
  4: "High",
  5: "Critical",
  6: "Fatal",
};

export function severityLabel(id: number): string {
  return SEVERITY_LABELS[id] ?? `Unknown(${id})`;
}

export function severityClass(id: number): string {
  switch (id) {
    case 6:
    case 5:
      return "bg-red-500/15 text-red-300 border-red-500/40";
    case 4:
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case 3:
      return "bg-yellow-500/10 text-yellow-200 border-yellow-500/30";
    case 2:
      return "bg-cyan-500/10 text-cyan-200 border-cyan-500/30";
    default:
      return "bg-slate-500/10 text-slate-300 border-slate-500/30";
  }
}

export function formatTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString([], {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  if (Number.isNaN(d)) return String(iso);
  const secs = Math.max(0, Math.floor((Date.now() - d) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

export function truncate(s: string | null | undefined, n = 120): string {
  if (!s) return "—";
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

export function jsonPretty(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

export function statusClass(status: string): string {
  switch (status) {
    case "open":
    case "new":
      return "bg-red-500/15 text-red-300 border-red-500/40";
    case "ack":
    case "investigating":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    case "contained":
      return "bg-cyan-500/15 text-cyan-200 border-cyan-500/40";
    case "resolved":
    case "closed":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
    case "false_positive":
    case "planned":
      return "bg-slate-500/15 text-slate-300 border-slate-400/30";
    default:
      return "bg-slate-500/10 text-slate-300 border-slate-500/30";
  }
}