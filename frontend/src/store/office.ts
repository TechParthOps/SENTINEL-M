/**
 * 3D Virtual Office state (Phase 6).
 *
 * Synchronization contract (honest telemetry only):
 *  - Room metrics come from real REST endpoints (stats, agents, intel, deception, aisec, media).
 *  - Live markers come only from actual WS bus topics (alerts/incidents/agents/response/deception).
 *  - An action/marker is only shown after the backend confirms it (WS frames are emitted by
 *    the backend after DB commit).
 *  - No random movement, no simulated attacks. Replay mode steps through REAL persisted alerts.
 */
import { create } from "zustand";
import { api } from "../lib/api";
import { live } from "../lib/ws";

export interface RoomDef {
  id: string;
  name: string;
  grid: [number, number];
  color: string;
}

export const ROOMS: RoomDef[] = [
  { id: "central", name: "Central Command", grid: [0, 0], color: "#22d3ee" },
  { id: "network", name: "Network Operations", grid: [1, 0], color: "#38bdf8" },
  { id: "intel", name: "Threat Intelligence", grid: [2, 0], color: "#a78bfa" },
  { id: "ai", name: "AI Security Lab", grid: [0, 1], color: "#f472b6" },
  { id: "forensics", name: "Digital Forensics Lab", grid: [1, 1], color: "#fbbf24" },
  { id: "incident", name: "Incident Response", grid: [2, 1], color: "#f87171" },
  { id: "deception", name: "Deception Operations", grid: [1, 2], color: "#34d399" },
];

export interface Marker {
  id: string;
  room: string;
  time: string;
  label: string;
  severity: number;
}

export interface RoomMetric {
  room: string;
  count: number;
  detail: string;
}

function roomForRule(ruleId: string): string {
  if (ruleId.startsWith("NET-") || ruleId.startsWith("WEB-")) return "network";
  if (ruleId.startsWith("INTEL-")) return "intel";
  if (ruleId.startsWith("DECEPTION-")) return "deception";
  if (ruleId.startsWith("AUTH-") || ruleId.startsWith("ID-")) return "central";
  if (ruleId.startsWith("HOST-") || ruleId.startsWith("FILE-")) return "forensics";
  return "incident";
}

interface OfficeState {
  connected: boolean;
  metrics: Record<string, RoomMetric>;
  markers: Marker[];
  replay: { active: boolean; paused: boolean; index: number; frames: Marker[] };
  agentsRunning: number;
  investigationsTotal: number;
  loadMetrics: () => Promise<void>;
  subscribeLive: () => () => void;
  startReplay: () => Promise<void>;
  toggleReplayPause: () => void;
  stopReplay: () => void;
}

const MAX_MARKERS = 24;

export const useOffice = create<OfficeState>((set, get) => ({
  connected: false,
  metrics: {},
  markers: [],
  agentsRunning: 0,
  investigationsTotal: 0,
  replay: { active: false, paused: false, index: 0, frames: [] },

  async loadMetrics() {
    try {
      const [stats, agents, deception, aisec, media, health, alertsRes] = await Promise.all([
        api.get<{
          events: { total: number };
          alerts: { open: number };
          intel: { indicators_active: number };
        }>("/stats/overview"),
        api.get<{ investigations: { id: string; status: string; verdict: string }[] }>(
          "/agents/investigations?limit=50"),
        api.get<{ pots: { id: string; status: string; interactions_count: number }[] }>("/deception/pots"),
        api.get<{ analyses: { id: string; verdict: string }[] }>("/aisec/analyses?limit=50"),
        api.get<{ analyses: { id: string; verdict: string }[] }>("/media/analyses?limit=50"),
        api.get<{ modules: Record<string, { status: string }> }>("/health"),
        api.get<{ alerts: { rule_id: string }[] }>("/alerts?limit=300"),
      ]);

      const runningAgents = agents.investigations.filter((i) => i.status === "running").length;
      const runningPots = deception.pots.filter((p) => p.status === "running");
      const potInteractions = deception.pots.reduce((n, p) => n + (p.interactions_count || 0), 0);
      const openAlerts = stats.alerts?.open ?? 0;
      const modulesOk = Object.values(health.modules ?? {}).filter((m) => m.status === "ok").length;

      // real per-room alert counts from persisted alert rows
      const roomCounts: Record<string, number> = {};
      for (const a of alertsRes.alerts) {
        const room = roomForRule(a.rule_id);
        roomCounts[room] = (roomCounts[room] ?? 0) + 1;
      }

      const metrics: Record<string, RoomMetric> = {
        central: {
          room: "central", count: roomCounts.central ?? 0,
          detail: `${stats.events?.total ?? 0} events retained · ${modulesOk} modules healthy · ${openAlerts} open alerts`,
        },
        network: { room: "network", count: roomCounts.network ?? 0, detail: "NET/WEB detections in the retained alert window" },
        intel: { room: "intel", count: stats.intel?.indicators_active ?? 0, detail: "active threat-intel indicators" },
        ai: { room: "ai", count: aisec.analyses.length, detail: "AI-security text analyses stored" },
        forensics: { room: "forensics", count: (roomCounts.forensics ?? 0) + media.analyses.length, detail: "host/file detections + stored media analyses" },
        incident: { room: "incident", count: agents.investigations.length, detail: `${runningAgents} investigation(s) running` },
        deception: { room: "deception", count: runningPots.length, detail: `${potInteractions} interactions captured across ${deception.pots.length} assets` },
      };
      set({ metrics, agentsRunning: runningAgents, investigationsTotal: agents.investigations.length });
    } catch {
      /* metrics refresh is best-effort; the page shows the last known values */
    }
  },

  subscribeLive() {
    const push = (m: Marker) =>
      set((s) => {
        // backend ids can repeat across frames (e.g. correlation republishes an
        // incident); suffix each marker so React keys stay unique
        const dedupe = `${m.id}#${s.markers.length + 1}-${Date.now()}`;
        return { markers: [{ ...m, id: dedupe }, ...s.markers].slice(0, MAX_MARKERS) };
      });
    const sub = live.onMessage((topic, data) => {
      if (topic === "alerts" && data) {
        const a = data as { id: string; rule_id: string; severity_id: number; time: string; rule_title: string };
        push({
          id: a.id, room: roomForRule(a.rule_id), time: a.time,
          label: `${a.rule_id}: ${a.rule_title}`, severity: a.severity_id,
        });
      } else if (topic === "incidents" && data) {
        const inc = data as { id?: string; title?: string; severity_id?: number };
        push({
          id: inc.id ?? String(Date.now()), room: "incident", time: new Date().toISOString(),
          label: `incident: ${inc.title ?? "correlated"}`, severity: inc.severity_id ?? 3,
        });
      } else if (topic === "agents" && data) {
        const ev = data as { type: string };
        if (ev.type === "investigation.created" || ev.type === "investigation.completed") {
          push({
            id: String(Date.now()) + ev.type, room: "incident",
            time: new Date().toISOString(), label: ev.type, severity: 3,
          });
        }
      } else if (topic === "response" && data) {
        const ev = data as { type: string; status?: string };
        push({
          id: String(Date.now()) + ev.type, room: "central", time: new Date().toISOString(),
          label: `response: ${ev.type}${ev.status ? ` (${ev.status})` : ""}`, severity: 4,
        });
      } else if (topic === "deception" && data) {
        const ev = data as { type: string; name?: string };
        push({
          id: String(Date.now()) + ev.type, room: "deception", time: new Date().toISOString(),
          label: `deception: ${ev.type}${ev.name ? ` (${ev.name})` : ""}`, severity: 4,
        });
      }
    });
    const poll = setInterval(() => {
      set({ connected: live.connected });
      void get().loadMetrics();
    }, 5000);
    set({ connected: live.connected });
    return () => {
      clearInterval(poll);
      sub();
    };
  },

  async startReplay() {
    // Replay REAL persisted alerts, oldest → newest, paused-capable. No synthetic frames.
    try {
      const res = await api.get<{ alerts: { id: string; time: string; rule_id: string; rule_title: string; severity_id: number }[] }>(
        "/alerts?limit=200");
      const frames: Marker[] = res.alerts
        .slice()
        .sort((a, b) => (a.time < b.time ? -1 : 1))
        .map((a) => ({
          id: a.id, room: roomForRule(a.rule_id), time: a.time,
          label: `${a.rule_id}: ${a.rule_title}`, severity: a.severity_id,
        }));
      set({ replay: { active: true, paused: false, index: 0, frames }, markers: [] });
    } catch {
      /* replay needs REST history; keep live view on failure */
    }
  },

  toggleReplayPause() {
    set((s) => ({ replay: { ...s.replay, paused: !s.replay.paused } }));
  },

  stopReplay() {
    set((s) => ({ replay: { active: false, paused: false, index: 0, frames: [] }, markers: [] }));
  },
}));
