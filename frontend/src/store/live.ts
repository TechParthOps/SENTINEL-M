import { create } from "zustand";
import { live } from "../lib/ws";

export interface LiveEvent {
  id: string;
  time: string;
  class_name: string;
  severity_id: number;
  message: string;
  host: string | null;
  src_ip: string | null;
  source_product: string;
}

export interface LiveAlert {
  id: string;
  time: string;
  rule_id: string;
  rule_title: string;
  severity_id: number;
  entity_key: string;
  status: string;
  message: string;
  incident_id: string | null;
}

interface LiveState {
  connected: boolean;
  events: LiveEvent[];
  alerts: LiveAlert[];
  connect: () => () => void;
  reset: () => void;
}

const MAX_ITEMS = 300;

export const useLive = create<LiveState>((set) => ({
  connected: false,
  events: [],
  alerts: [],

  connect() {
    const sub = live.onMessage((topic, data) => {
      if (topic === "events" && data) {
        const e = data as LiveEvent;
        set((s) => ({ events: [e, ...s.events].slice(0, MAX_ITEMS) }));
      } else if (topic === "alerts" && data) {
        const a = data as LiveAlert;
        set((s) => ({ alerts: [a, ...s.alerts].slice(0, MAX_ITEMS) }));
      } else if (topic === "assets") {
        /* asset updates are pulled on demand by the Assets page */
      }
    });
    live.start();
    const poll = setInterval(() => set({ connected: live.connected }), 1000);
    return () => {
      sub();
      live.stop();
      clearInterval(poll);
    };
  },

  reset() {
    set({ events: [], alerts: [] });
  },
}));