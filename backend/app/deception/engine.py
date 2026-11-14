"""Deception / honeypot engine (Phase 5).

Isolation contract (documented, enforced in code):
  - Listeners bind to 127.0.0.1 by default (SENTINEL_DECEPTION_BIND to change) and are
    always unprivileged, resource-capped threads — never proxies into production services.
  - Decoy credentials are generated RANDOMLY at creation. The engine never reads the real
    user inventory. Plaintext decoy passwords are not stored (hash only).
  - Interactions are recorded and raised as real DECEPTION-HP-001 alerts so they flow
    through the normal detection/correlation/live-UI pipeline.
  - Safe termination: stop() closes sockets and joins threads; nothing is left running.
"""
from __future__ import annotations

import hashlib
import secrets
import socket
import socketserver
import threading
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.bus import bus
from app.core.config import settings
from app.deception.models import Honeypot, HoneypotInteraction

KINDS = ("http_login", "tcp_banner", "canary_token")


def _publish(event_type: str, data: dict) -> None:
    bus.publish("deception", {"type": event_type, **data})


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.request.sendall(b"SSH-2.0-OpenSSH_8.9p1\r\n")  # decoy banner
            data = self.request.recv(256)[:256]
            honeypot_id = self.server.honeypot_id  # type: ignore[attr-defined]
            deception_engine.record_interaction(
                honeypot_id, source_ip=self.client_address[0], kind="tcp_connect",
                detail={"payload_preview": data.decode("utf-8", "replace")[:128]},
            )
        except Exception:
            pass


class DeceptionEngine:
    def __init__(self) -> None:
        self._servers: dict[str, socketserver.ThreadingTCPServer] = {}
        self._threads: dict[str, threading.Thread] = {}

    # ------------------------------------------------------------- lifecycle
    def create(self, db: Session, name: str, kind: str, port: int, actor: str) -> Honeypot:
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {KINDS}")
        if db.query(Honeypot).filter(Honeypot.name == name).first():
            raise ValueError("a honeypot with this name already exists")
        decoy_user = f"svc-{secrets.token_hex(3)}"
        decoy_secret = secrets.token_urlsafe(18)
        pot = Honeypot(
            id=str(uuid.uuid4()), name=name[:128], kind=kind, port=int(port),
            decoy_identity=decoy_user[:64],
            decoy_secret_sha256=hashlib.sha256(decoy_secret.encode()).hexdigest(),
            canary_path=f"/deception/canary/{uuid.uuid4().hex[:16]}" if kind == "canary_token" else "",
            settings={"bind": settings.deception_bind},
            created_by=actor[:128],
        )
        db.add(pot)
        db.commit()
        db.refresh(pot)
        _publish("honeypot.created", self._public(pot))
        return pot

    def start(self, db: Session, pot: Honeypot) -> Honeypot:
        if pot.kind == "canary_token":
            pot.status = "running"  # canaries are passive URL tokens; no listener needed
            db.commit()
            _publish("honeypot.started", self._public(pot))
            return pot
        if pot.id in self._servers:
            raise ValueError("listener already running")
        if not (1024 <= pot.port <= 65535):
            raise ValueError("port must be in 1024..65535 (unprivileged only)")

        bind = settings.deception_bind

        class _Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            request_queue_size = 8

        srv = _Server((bind, int(pot.port)), _BannerHandler)
        srv.honeypot_id = pot.id  # type: ignore[attr-defined]
        t = threading.Thread(target=srv.serve_forever, name=f"honeypot-{pot.id[:8]}", daemon=True)
        t.start()
        self._servers[pot.id] = srv
        self._threads[pot.id] = t
        pot.status = "running"
        db.commit()
        _publish("honeypot.started", self._public(pot))
        return pot

    def stop(self, db: Session, pot: Honeypot) -> Honeypot:
        srv = self._servers.pop(pot.id, None)
        t = self._threads.pop(pot.id, None)
        if srv is not None:
            srv.shutdown()
            srv.server_close()
        if t is not None:
            t.join(timeout=5)
        pot.status = "stopped"
        db.commit()
        _publish("honeypot.stopped", self._public(pot))
        return pot

    def stop_all(self, db: Session) -> None:
        for pot in db.query(Honeypot).filter(Honeypot.status == "running").all():
            try:
                self.stop(db, pot)
            except Exception:
                continue

    # ------------------------------------------------------------- interactions
    def record_interaction(self, honeypot_id: str, source_ip: str, kind: str, detail: dict) -> None:
        from app.core.database import SessionLocal

        db = SessionLocal()
        try:
            pot = db.get(Honeypot, honeypot_id)
            if pot is None or pot.status != "running":
                return
            row = HoneypotInteraction(
                id=str(uuid.uuid4()), honeypot_id=honeypot_id,
                time=datetime.now(timezone.utc).replace(tzinfo=None),
                source_ip=source_ip[:45], kind=kind[:32], detail=detail,
            )
            pot.interactions_count = (pot.interactions_count or 0) + 1
            db.add(row)
            db.commit()
            self._raise_alert(db, pot, row)
            _publish("honeypot.interaction",
                     {"honeypot_id": honeypot_id, "name": pot.name, "kind": kind,
                      "source_ip": source_ip, "detail": detail})
        finally:
            db.close()

    def canary_hit(self, db: Session, path: str, source_ip: str, detail: dict):
        pot = db.query(Honeypot).filter(Honeypot.canary_path == path, Honeypot.kind == "canary_token").first()
        if pot is None:
            return None
        row = HoneypotInteraction(
            id=str(uuid.uuid4()), honeypot_id=pot.id,
            time=datetime.now(timezone.utc).replace(tzinfo=None),
            source_ip=source_ip[:45], kind="canary_hit", detail=detail,
        )
        pot.interactions_count = (pot.interactions_count or 0) + 1
        db.add(row)
        db.commit()
        self._raise_alert(db, pot, row)
        _publish("honeypot.interaction",
                 {"honeypot_id": pot.id, "name": pot.name, "kind": "canary_hit",
                  "source_ip": source_ip, "detail": detail})
        return pot

    def _raise_alert(self, db: Session, pot: Honeypot, row: HoneypotInteraction) -> None:
        from app.models.alert import Alert

        alert = Alert(
            id=str(uuid.uuid4()), time=row.time, rule_id="DECEPTION-HP-001",
            rule_title="Deception asset interaction",
            category="deception_interaction", severity_id=4,
            entity_key=pot.name, entity_type="deception",
            attack_ids=["T1018"], evidence_event_ids=[row.id],
            status="new", source_product="sentinel-deception",
            message=f"Interaction ({row.kind}) with {pot.kind} honeypot '{pot.name}' from {row.source_ip}",
        )
        db.add(alert)
        db.commit()
        _publish("honeypot.alert", {"honeypot_id": pot.id, "alert_id": alert.id})

    # ------------------------------------------------------------- queries
    def list_pots(self, db: Session) -> list[dict]:
        return [self._public(p) for p in db.query(Honeypot).order_by(Honeypot.created_at.desc()).all()]

    def interactions(self, db: Session, pot_id: str, limit: int = 100) -> list[dict]:
        rows = (
            db.query(HoneypotInteraction)
            .filter(HoneypotInteraction.honeypot_id == pot_id)
            .order_by(HoneypotInteraction.time.desc())
            .limit(limit).all()
        )
        return [
            {"id": r.id, "time": r.time.isoformat() if r.time else None,
             "source_ip": r.source_ip, "kind": r.kind, "detail": r.detail}
            for r in rows
        ]

    def _public(self, p: Honeypot) -> dict:
        return {
            "id": p.id, "name": p.name, "kind": p.kind, "port": p.port,
            "status": p.status, "decoy_identity": p.decoy_identity,
            "canary_path": p.canary_path, "interactions_count": p.interactions_count,
            "created_by": p.created_by,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }

    def health(self) -> dict:
        return {
            "status": "ok",
            "listeners_running": len(self._servers),
            "bind_default": settings.deception_bind,
            "isolation": "loopback default, unprivileged ports, random decoy credentials, no production data",
        }


deception_engine = DeceptionEngine()
