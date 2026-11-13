/** Live WebSocket stream client (ADR-007) with auto-reconnect. */
import { getToken } from "./api";

export type WsHandler = (topic: string, data: unknown) => void;

export class LiveStream {
  private ws: WebSocket | null = null;
  private handlers = new Set<WsHandler>();
  private stopped = false;
  private retry = 0;

  onMessage(handler: WsHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  start(): void {
    this.stopped = false;
    this.connect();
  }

  stop(): void {
    this.stopped = true;
    this.ws?.close();
    this.ws = null;
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private connect(): void {
    if (this.stopped) return;
    const token = getToken();
    if (!token) return;
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const url = `${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(url);
    this.ws = ws;
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.topic === "connected") return;
        this.handlers.forEach((h) => h(msg.topic, msg.data));
      } catch {
        /* malformed frame: ignore */
      }
    };
    ws.onclose = () => {
      if (this.stopped) return;
      const delay = Math.min(15000, 1000 * 2 ** this.retry++);
      setTimeout(() => this.connect(), delay);
    };
  }
}

export const live = new LiveStream();