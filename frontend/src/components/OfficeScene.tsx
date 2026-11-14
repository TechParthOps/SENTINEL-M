/**
 * OfficeScene — R3F 3D virtual security-operations office (Phase 6).
 *
 * A realistic SOC environment: partitioned rooms with door gaps and glass
 * partitions, desks with monitors and chairs, wall signage, a central video
 * wall, ceiling beams, and an open collaboration area.
 *
 * Data honesty (ADR-008): every screen, beacon and marker is driven by REAL
 * backend numbers (REST room counts) and WS-confirmed event markers. The scene
 * is static — no animation, no simulated staff, no scripted attacks. The only
 * motion is the camera the operator controls.
 */
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Canvas, useFrame, useThree } from "@react-three/fiber";
import * as THREE from "three";
import { ROOMS, useOffice } from "../store/office";

const GRID_SPACING = 6;
const ROOM_W = 5.2;
const WALL_H = 2.2;
const WALL_T = 0.16;
const DOOR_W = 1.7;
const MAX3D = 14;

/** Canvas texture for wall signage and monitors (static, memoized by content). */
function panelTexture(title: string, line2: string, accent: string, big = false): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 512;
  canvas.height = 256;
  const ctx = canvas.getContext("2d")!;
  ctx.fillStyle = "#050b12";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.strokeStyle = accent;
  ctx.lineWidth = 6;
  ctx.strokeRect(3, 3, canvas.width - 6, canvas.height - 6);
  ctx.textAlign = "center";
  ctx.fillStyle = accent;
  ctx.font = "700 44px system-ui, sans-serif";
  ctx.fillText(title.slice(0, 22), canvas.width / 2, big ? 96 : 92);
  ctx.fillStyle = "#e2e8f0";
  ctx.font = big ? "700 130px system-ui, sans-serif" : "600 96px system-ui, sans-serif";
  ctx.fillText(line2, canvas.width / 2, big ? 232 : 220);
  const tex = new THREE.CanvasTexture(canvas);
  tex.needsUpdate = true;
  return tex;
}

/** A wall segment (or two segments with a centered door gap). */
function Wall({ width, position, rotationZ = 0, glass = false }: {
  width: number;
  position: [number, number, number];
  rotationZ?: number;
  glass?: boolean;
}) {
  return (
    <group position={position} rotation={[0, rotationZ, 0]}>
      <mesh position={[0, WALL_H / 2, 0]}>
        <boxGeometry args={[width, WALL_H, WALL_T]} />
        <meshStandardMaterial color="#16222f" roughness={0.9} />
      </mesh>
      {/* glass strip above the solid base — SOC open-plan look */}
      <mesh position={[0, WALL_H + 0.35, 0]}>
        <boxGeometry args={[width, 0.7, WALL_T * 0.6]} />
        <meshStandardMaterial
          color={glass ? "#67e8f9" : "#94a3b8"}
          transparent
          opacity={glass ? 0.16 : 0.06}
          emissive={glass ? "#22d3ee" : "#000000"}
          emissiveIntensity={0.25}
        />
      </mesh>
    </group>
  );
}

function WallSign({ text, color, position, rotationY }: {
  text: string;
  color: string;
  position: [number, number, number];
  rotationY: number;
}) {
  const tex = useMemo(() => panelTexture(text, "", color), [text, color]);
  return (
    <mesh position={position} rotation={[0, rotationY, 0]}>
      <planeGeometry args={[2.6, 1.3]} />
      <meshStandardMaterial map={tex} transparent emissive="#0e7490" emissiveIntensity={0.35} />
    </mesh>
  );
}

/** Desk + chair + wall-monitor + activity beacon tube. All sizes in meters. */
function DeskUnit({ roomColor, count, label, screenPos }: {
  roomColor: string;
  count: number;
  label: string;
  screenPos: [number, number, number];
}) {
  const active = count > 0;
  const barH = Math.min(1.5, 0.18 + Math.log2(count + 1) * 0.72);
  const screen = useMemo(
    () => panelTexture(label, String(count), roomColor),
    [label, count, roomColor],
  );
  return (
    <group>
      {/* tabletop + legs */}
      <mesh position={[0, 0.74, 0]}>
        <boxGeometry args={[1.9, 0.07, 0.95]} />
        <meshStandardMaterial color="#1e293b" roughness={0.8} />
      </mesh>
      {[[-0.82, -0.38], [0.82, -0.38], [-0.82, 0.38], [0.82, 0.38]].map(([lx, lz], i) => (
        <mesh key={i} position={[lx, 0.37, lz]}>
          <boxGeometry args={[0.06, 0.74, 0.06]} />
          <meshStandardMaterial color="#334155" />
        </mesh>
      ))}
      {/* monitor */}
      <group position={screenPos}>
        <mesh position={[0, 0.05, 0]}>
          <boxGeometry args={[0.08, 0.5, 0.08]} />
          <meshStandardMaterial color="#475569" />
        </mesh>
        <mesh position={[0, 0.42, 0]} rotation={[-0.12, 0, 0]}>
          <planeGeometry args={[1.15, 0.66]} />
          <meshStandardMaterial
            map={screen}
            emissive="#0f172a"
            emissiveIntensity={active ? 0.9 : 0.15}
            toneMapped={false}
          />
        </mesh>
      </group>
      {/* activity beacon: glass tube with an emissive core scaled by REAL volume */}
      <mesh position={[1.0, 0.85, 0]}>
        <cylinderGeometry args={[0.05, 0.05, 1.7, 12]} />
        <meshStandardMaterial color="#0ea5e9" transparent opacity={0.18} />
      </mesh>
      <mesh position={[1.0, 0.05 + barH / 2, 0]}>
        <cylinderGeometry args={[0.035, 0.035, Math.max(0.02, barH), 10]} />
        <meshStandardMaterial
          color={roomColor}
          emissive={roomColor}
          emissiveIntensity={active ? 1.1 : 0.08}
        />
      </mesh>
      {/* chair */}
      <group position={[0, 0, -1.0]} rotation={[0, Math.PI, 0]}>
        <mesh position={[0, 0.45, 0]}>
          <cylinderGeometry args={[0.26, 0.24, 0.08, 14]} />
          <meshStandardMaterial color="#0f172a" />
        </mesh>
        <mesh position={[0, 0.72, 0.24]}>
          <boxGeometry args={[0.5, 0.55, 0.07]} />
          <meshStandardMaterial color="#0f172a" />
        </mesh>
      </group>
    </group>
  );
}

function labelTexture(text: string, color: string): THREE.CanvasTexture {
  const canvas = document.createElement("canvas");
  canvas.width = 512;
  canvas.height = 128;
  const ctx = canvas.getContext("2d")!;
  ctx.fillStyle = "rgba(6,12,20,0.85)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = "600 44px system-ui, sans-serif";
  ctx.fillStyle = color;
  ctx.textAlign = "center";
  ctx.fillText(text, canvas.width / 2, canvas.height / 2 + 16);
  const tex = new THREE.CanvasTexture(canvas);
  tex.needsUpdate = true;
  return tex;
}

function RoomLabel({ text, color, position }: { text: string; color: string; position: [number, number, number] }) {
  const tex = labelTexture(text, color);
  return (
    <sprite position={position} scale={[4.6, 1.15, 1]}>
      <spriteMaterial map={tex} transparent depthWrite={false} />
    </sprite>
  );
}

/** One partitioned room: floor, walls with a door gap + signage, glass strip. */
function RoomShell({ id, name, grid, color, count, onClick, children }: {
  id: string;
  name: string;
  grid: [number, number];
  color: string;
  count: number;
  onClick: (id: string) => void;
  children?: ReactNode;
}) {
  const [hovered, setHovered] = useState(false);
  const [x, z] = [grid[0] * GRID_SPACING, grid[1] * GRID_SPACING];
  const half = ROOM_W / 2;
  const dx = -grid[0];
  const dz = -grid[1];
  // door faces Central Command; Central itself has doors on its two open sides
  const doorOnX = id === "central" ? null : Math.abs(dx) >= Math.abs(dz) ? (dx > 0 ? 1 : -1) : null;
  const doorOnZ = id === "central" ? null : doorOnX === null ? (dz > 0 ? 1 : -1) : null;
  const halfSeg = (ROOM_W - DOOR_W) / 2;

  return (
    <group position={[x, 0, z]}>
      {/* floor plate (the click target: whole room selects) */}
      <mesh
        position={[0, 0.02, 0]}
        rotation={[-Math.PI / 2, 0, 0]}
        onPointerOver={() => setHovered(true)}
        onPointerOut={() => setHovered(false)}
        onClick={() => onClick(id)}
      >
        <planeGeometry args={[ROOM_W, ROOM_W]} />
        <meshStandardMaterial color={hovered ? "#134e5c" : "#0c1622"} />
      </mesh>

      {/* x-axis walls (run along z) */}
      {(id === "central" ? [1] : [1, -1]).map((sx) => {
        const gap = doorOnX === sx;
        return (
          <group key={`x${sx}`}>
            {gap ? (
              <>
                <group position={[sx * half, 0, -halfSeg / 2 - DOOR_W / 2]} rotation={[0, Math.PI / 2, 0]}>
                  <Wall width={DOOR_W} position={[0, 0, 0]} glass />
                  <mesh position={[0, WALL_H + 0.75, 0]}>
                    <boxGeometry args={[DOOR_W, 1.5, 0.05]} />
                    <meshStandardMaterial color="#67e8f9" transparent opacity={0.07} />
                  </mesh>
                </group>
                <group position={[sx * half, 0, half + halfSeg / 2]} rotation={[0, Math.PI / 2, 0]}>
                  <Wall width={halfSeg} position={[0, 0, 0]} />
                </group>
                <group position={[sx * half, 0, -half - halfSeg / 2]} rotation={[0, Math.PI / 2, 0]}>
                  <Wall width={halfSeg} position={[0, 0, 0]} />
                </group>
                <WallSign
                  text={name}
                  color={color}
                  position={[sx * (half - 0.12), WALL_H + 0.35, 0]}
                  rotationY={sx > 0 ? -Math.PI / 2 : Math.PI / 2}
                />
              </>
            ) : (
              <group position={[sx * half, 0, 0]} rotation={[0, Math.PI / 2, 0]}>
                <Wall width={ROOM_W} position={[0, 0, 0]} glass={grid[0] === 0 || grid[0] === 2} />
              </group>
            )}
          </group>
        );
      })}

      {/* z-axis walls (run along x) */}
      {(id === "central" ? [1] : [1, -1]).map((sz) => {
        const gap = doorOnZ === sz;
        return (
          <group key={`z${sz}`}>
            {gap ? (
              <>
                <group position={[-halfSeg / 2 - DOOR_W / 2, 0, sz * half]}>
                  <Wall width={DOOR_W} position={[0, 0, 0]} glass />
                  <mesh position={[0, WALL_H + 0.75, 0]}>
                    <boxGeometry args={[DOOR_W, 1.5, 0.05]} />
                    <meshStandardMaterial color="#67e8f9" transparent opacity={0.07} />
                  </mesh>
                </group>
                <group position={[half + halfSeg / 2, 0, sz * half]}>
                  <Wall width={halfSeg} position={[0, 0, 0]} />
                </group>
                <group position={[-half - halfSeg / 2, 0, sz * half]}>
                  <Wall width={halfSeg} position={[0, 0, 0]} />
                </group>
                <WallSign
                  text={name}
                  color={color}
                  position={[0, WALL_H + 0.35, sz * (half - 0.12)]}
                  rotationY={sz > 0 ? 0 : Math.PI}
                />
              </>
            ) : (
              <group position={[0, 0, sz * half]}>
                <Wall width={ROOM_W} position={[0, 0, 0]} glass={grid[1] === 0 || grid[1] === 2} />
              </group>
            )}
          </group>
        );
      })}

      {children}
    </group>
  );
}

/** Central Command video wall: one screen per monitored room, real counts. */
function VideoWall({ onClick }: { onClick: (room: string) => void }) {
  const metrics = useOffice((s) => s.metrics);
  return (
    <group position={[0, 0, -ROOM_W / 2 + 0.35]}>
      <mesh position={[0, 0.78, -0.12]}>
        <boxGeometry args={[4.9, 0.07, 0.5]} />
        <meshStandardMaterial color="#1e293b" />
      </mesh>
      {ROOMS.filter((r) => r.id !== "central").map((r, i) => {
        const count = metrics[r.id]?.count ?? 0;
        const col = i % 3;
        const row = Math.floor(i / 3);
        return (
          <group key={r.id} position={[-1.6 + col * 1.6, 1.55 + row * 1.05, 0]}>
            <mesh onClick={() => onClick(r.id)}>
              <planeGeometry args={[1.45, 0.78]} />
              <meshStandardMaterial
                map={panelTexture(r.name, String(count), r.color, true)}
                emissive="#0f172a"
                emissiveIntensity={count > 0 ? 0.9 : 0.12}
                toneMapped={false}
              />
            </mesh>
            <mesh position={[0, 0, -0.05]}>
              <boxGeometry args={[1.5, 0.83, 0.05]} />
              <meshStandardMaterial color={r.color} emissive={r.color} emissiveIntensity={count > 0 ? 0.5 : 0.08} />
            </mesh>
          </group>
        );
      })}
    </group>
  );
}

function Markers() {
  const markers = useOffice((s) => s.markers);
  const replay = useOffice((s) => s.replay);
  const shown = replay.active
    ? replay.frames.slice(0, replay.index + 1).slice(-MAX3D)
    : markers.slice(0, MAX3D);
  const byRoom: Record<string, { y: number; severity: number; key: string }[]> = {};
  shown.forEach((m, i) => {
    const arr = byRoom[m.room] ?? (byRoom[m.room] = []);
    arr.push({ y: 2.6 + (arr.length % 3) * 0.9, severity: m.severity, key: `${m.id}-${i}` });
  });
  return (
    <>
      {Object.entries(byRoom).flatMap(([room, items]) =>
        items.map((it, n) => {
          const def = ROOMS.find((r) => r.id === room)!;
          const color = it.severity >= 5 ? "#ef4444" : it.severity >= 4 ? "#f59e0b" : "#22d3ee";
          const angle = (n / Math.max(1, items.length)) * Math.PI * 2;
          const x = def.grid[0] * GRID_SPACING + Math.cos(angle) * 1.9;
          const z = def.grid[1] * GRID_SPACING + Math.sin(angle) * 1.9;
          return (
            <mesh key={it.key} position={[x, it.y, z]}>
              <octahedronGeometry args={[0.28]} />
              <meshStandardMaterial color={color} emissive={color} emissiveIntensity={0.8} />
            </mesh>
          );
        }),
      )}
    </>
  );
}

function CameraRig() {
  const { camera, gl } = useThree();
  const state = useRef({ dragging: false, lx: 0, ly: 0, theta: Math.PI / 4, phi: 0.9, dist: 22 });

  useEffect(() => {
    const el = gl.domElement;
    const onDown = (e: PointerEvent) => {
      state.current.dragging = true;
      state.current.lx = e.clientX;
      state.current.ly = e.clientY;
    };
    const onMove = (e: PointerEvent) => {
      if (!state.current.dragging) return;
      const s = state.current;
      s.theta -= (e.clientX - s.lx) * 0.006;
      s.phi = Math.min(1.45, Math.max(0.35, s.phi - (e.clientY - s.ly) * 0.005));
      s.lx = e.clientX;
      s.ly = e.clientY;
    };
    const onUp = () => (state.current.dragging = false);
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      state.current.dist = Math.min(45, Math.max(8, state.current.dist + e.deltaY * 0.02));
    };
    el.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => {
      el.removeEventListener("pointerdown", onDown);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      el.removeEventListener("wheel", onWheel);
    };
  }, [gl]);

  useFrame(() => {
    const s = state.current;
    camera.position.set(
      Math.sin(s.phi) * Math.cos(s.theta) * s.dist,
      Math.cos(s.phi) * s.dist,
      Math.sin(s.phi) * Math.sin(s.theta) * s.dist,
    );
    camera.lookAt(GRID_SPACING, 0, GRID_SPACING);
  });
  return null;
}

/** Furniture dressing for the open collaboration cell (no metrics attached). */
function Lounge() {
  return (
    <group position={[0, 0, GRID_SPACING * 2]}>
      <mesh position={[0, 0.02, 0]} rotation={[-Math.PI / 2, 0, 0]}>
        <planeGeometry args={[ROOM_W, ROOM_W]} />
        <meshStandardMaterial color="#0c1622" />
      </mesh>
      {[[-1.4, 1.2], [1.4, 1.2]].map(([lx, lz], i) => (
        <group key={i} position={[lx, 0, lz]}>
          <mesh position={[0, 0.38, 0]}>
            <boxGeometry args={[1.3, 0.35, 0.55]} />
            <meshStandardMaterial color="#1e293b" />
          </mesh>
          <mesh position={[0, 0.62, -0.22]}>
            <boxGeometry args={[1.3, 0.5, 0.12]} />
            <meshStandardMaterial color="#1e293b" />
          </mesh>
        </group>
      ))}
      <mesh position={[0, 0.34, 0]}>
        <cylinderGeometry args={[0.5, 0.42, 0.06, 18]} />
        <meshStandardMaterial color="#334155" />
      </mesh>
    </group>
  );
}

/** Building shell: floor, perimeter walls, ceiling beams, one light per room. */
function OfficeShell() {
  const half = GRID_SPACING * 1.5 + 2.6;
  return (
    <group position={[GRID_SPACING, 0, GRID_SPACING]}>
      <mesh rotation={[-Math.PI / 2, 0, 0]} position={[0, -0.04, 0]}>
        <planeGeometry args={[half * 2, half * 2]} />
        <meshStandardMaterial color="#070d16" />
      </mesh>
      {/* perimeter */}
      {[[0, -half, 0], [0, half, 0]].map(([x, z, rz], i) => (
        <group key={`pz${i}`} position={[x, 0, z]}>
          <Wall width={half * 2} position={[0, 0, 0]} />
        </group>
      ))}
      {[[-half, 0, Math.PI / 2], [half, 0, Math.PI / 2]].map(([x, z, rz], i) => (
        <group key={`px${i}`} position={[x, 0, z]} rotation={[0, rz, 0]}>
          <Wall width={half * 2} position={[0, 0, 0]} />
        </group>
      ))}
      {/* ceiling beams (perimeter ring, middle stays open for the orbit camera) */}
      {[-half, 0, half].map((z, i) => (
        <mesh key={`b${i}`} position={[0, 3.3, z]}>
          <boxGeometry args={[half * 2, 0.12, 0.3]} />
          <meshStandardMaterial color="#111c29" />
        </mesh>
      ))}
    </group>
  );
}

export default function OfficeScene({ onRoomClick }: { onRoomClick: (room: string) => void }) {
  const metrics = useOffice((s) => s.metrics);
  return (
    <Canvas camera={{ position: [16, 18, 16], fov: 50 }} dpr={[1, 1.5]}>
      <color attach="background" args={["#04080f"]} />
      <ambientLight intensity={0.45} />
      <directionalLight position={[10, 20, 10]} intensity={0.7} />
      <OfficeShell />
      {ROOMS.map((r) => {
        const count = metrics[r.id]?.count ?? 0;
        return (
          <RoomShell
            key={r.id}
            id={r.id}
            name={r.name}
            grid={r.grid}
            color={r.color}
            count={count}
            onClick={onRoomClick}
          >
            {r.id === "central" ? (
              <>
                <VideoWall onClick={onRoomClick} />
                <group position={[0, 0, 1.55]}>
                  <mesh position={[0, 0.74, 0]}>
                    <boxGeometry args={[2.6, 0.07, 0.9]} />
                    <meshStandardMaterial color="#1e293b" />
                  </mesh>
                </group>
              </>
            ) : (
              <>
                <group position={[-1.15, 0, 1.0]}>
                  <DeskUnit roomColor={r.color} count={count} label={r.name} screenPos={[0, 1.15, 0.5]} />
                </group>
                <group position={[1.15, 0, 1.0]}>
                  <DeskUnit roomColor={r.color} count={count} label={r.name} screenPos={[0, 1.15, 0.5]} />
                </group>
                <pointLight position={[0, 2.2, 0]} intensity={0.4} distance={9} color={r.color} />
              </>
            )}
          </RoomShell>
        );
      })}
      <Lounge />
      <Markers />
      <CameraRig />
    </Canvas>
  );
}
