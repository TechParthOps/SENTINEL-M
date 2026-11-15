import { useEffect, useState } from "react";
import OfficeScene from "../components/OfficeScene";
import { ROOMS, useOffice } from "../store/office";
import { Badge, Button, Card, Empty, ErrorBox, Spinner } from "../components/ui";
import { formatTime } from "../lib/format";

export default function VirtualOfficePage() {
  const connected = useOffice((s) => s.connected);
  const agentsRunning = useOffice((s) => s.agentsRunning);
  const metrics = useOffice((s) => s.metrics);
  const markers = useOffice((s) => s.markers);
  const replay = useOffice((s) => s.replay);
  const loadMetrics = useOffice((s) => s.loadMetrics);
  const subscribeLive = useOffice((s) => s.subscribeLive);
  const startReplay = useOffice((s) => s.startReplay);
  const toggleReplayPause = useOffice((s) => s.toggleReplayPause);
  const stopReplay = useOffice((s) => s.stopReplay);
  const [selectedRoom, setSelectedRoom] = useState<string | null>(null);
  const [webglFailed, setWebglFailed] = useState(false);
  // during replay the list mirrors the replay frames up to the current index
  const shownMarkers = replay.active ? replay.frames.slice(0, replay.index + 1) : markers;

  useEffect(() => {
    void loadMetrics();
    const dispose = subscribeLive();
    return dispose;
  }, [loadMetrics, subscribeLive]);

  // replay stepper: advances through REAL persisted alert frames
  useEffect(() => {
    if (!replay.active || replay.paused) return;
    if (replay.index >= replay.frames.length - 1) return;
    const t = setTimeout(() => {
      useOffice.setState((s) => ({ replay: { ...s.replay, index: s.replay.index + 1 } }));
    }, 900);
    return () => clearTimeout(t);
  }, [replay.active, replay.paused, replay.index, replay.frames.length]);

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">3D Virtual Office</h1>
          <p className="text-sm text-sentinel-muted">
            Live digital twin of the security operation. Every room reflects real backend
            telemetry - alerts, investigations, intel, deception - synced over the WebSocket
            bus. Drag to orbit, scroll to zoom, click a room for detail.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <Badge className={connected
            ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-200"
            : "border-amber-500/40 bg-amber-500/15 text-amber-200"}>
            {connected ? "live sync active" : "connecting…"}
          </Badge>
          <Badge className={agentsRunning > 0
            ? "border-cyan-500/40 bg-cyan-500/15 text-cyan-200"
            : "border-slate-500/40 bg-slate-500/15 text-slate-300"}>
            {agentsRunning > 0 ? `${agentsRunning} agent task(s) running` : "no agent task running"}
          </Badge>
          {replay.active ? (
            <>
              <Button variant="ghost" onClick={toggleReplayPause}>
                {replay.paused ? "Resume replay" : "Pause replay"}
              </Button>
              <Button variant="ghost" onClick={stopReplay}>Exit replay</Button>
              <span className="text-slate-400">
                frame {replay.index + 1}/{replay.frames.length}
              </span>
            </>
          ) : (
            <Button variant="ghost" onClick={startReplay}>Replay history</Button>
          )}
        </div>
      </header>

      {webglFailed && (
        <ErrorBox>
          WebGL initialization failed - showing the 2D fallback below (same live data).
        </ErrorBox>
      )}

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <Card title="Operations floor" subtitle="Room pillar height = real activity volume; octahedra = confirmed events">
            <div className="h-[440px] overflow-hidden rounded-lg border border-sentinel-border">
              {webglFailed ? (
                <div className="flex h-full items-center justify-center text-sm text-slate-400">
                  3D view unavailable - 2D fallback active below.
                </div>
              ) : (
                <WebglGuard onFail={() => setWebglFailed(true)} onRoomClick={setSelectedRoom} />
              )}
            </div>
          </Card>
        </div>

        <div className="space-y-4">
          {selectedRoom && (
            <Card
              title={ROOMS.find((r) => r.id === selectedRoom)?.name ?? selectedRoom}
              subtitle={metrics[selectedRoom]?.detail}
              right={
                <Badge className="border-cyan-500/40 bg-cyan-500/15 text-cyan-200">
                  {metrics[selectedRoom]?.count ?? 0}
                </Badge>
              }
            >
              <p className="text-xs text-slate-400">
                Metrics from REST ({selectedRoom}); markers below arrived only after backend
                confirmation over WS.
              </p>
            </Card>
          )}

          <Card title="Confirmed event markers" subtitle={replay.active ? "replay of persisted alerts" : "live WS stream"}>
            {shownMarkers.length === 0 ? (
              <Empty>No confirmed events in the current window yet.</Empty>
            ) : (
              <div className="max-h-64 space-y-1 overflow-y-auto">
                {shownMarkers.slice(0, 12).map((m) => (
                  <div key={m.id} className="flex items-center gap-2 rounded border border-sentinel-border/50 px-2 py-1 text-xs">
                    <span className="font-mono text-slate-500">{formatTime(m.time)}</span>
                    <span className="text-slate-300">{m.label}</span>
                    <span className="ml-auto text-slate-500">
                      {ROOMS.find((r) => r.id === m.room)?.name}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {/* 2D fallback: same data, no WebGL */}
          <Card title="2D fallback view" subtitle="Identical live data without WebGL">
            <div className="grid grid-cols-2 gap-2">
              {ROOMS.map((r) => (
                <button
                  key={r.id}
                  onClick={() => setSelectedRoom(r.id)}
                  className={`rounded-lg border p-2 text-left text-xs ${
                    selectedRoom === r.id ? "border-cyan-500/60" : "border-sentinel-border"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">{r.name}</span>
                    <span className="font-mono text-cyan-300">{metrics[r.id]?.count ?? 0}</span>
                  </div>
                  <div className="mt-1 text-[10px] text-slate-500">{metrics[r.id]?.detail}</div>
                </button>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function WebglGuard({ onFail, onRoomClick }: { onFail: () => void; onRoomClick: (r: string) => void }) {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const canvas = document.createElement("canvas");
    const ok = !!(canvas.getContext("webgl2") || canvas.getContext("webgl"));
    if (!ok) onFail();
    setReady(ok);
  }, [onFail]);
  if (!ready) return <Spinner label="Preparing 3D view…" />;
  return <OfficeScene onRoomClick={onRoomClick} />;
}
