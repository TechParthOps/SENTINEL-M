"""Hash-chained append-only audit log (tamper-evident, Part 16)."""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.audit import AuditLog

_state_lock = threading.Lock()
_state: dict | None = None  # {"last_hash": str|None, "count": int}


def _canonical(entry: dict) -> str:
    payload = {
        "seq": entry["seq"],
        "ts": entry["ts"],
        "action": entry["action"],
        "actor": entry["actor"],
        "details": entry["details"],
        "prev_hash": entry["prev_hash"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _load_state(db: Session) -> dict:
    last = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one_or_none()
    if last is None:
        return {"last_hash": None, "count": 0}
    return {"last_hash": last.entry_hash, "count": last.id}


def record(action: str, actor: str = "system", details: dict | None = None, db: Session | None = None) -> AuditLog:
    """Append an audit entry. Uses its own session unless one is supplied."""
    own = db is None
    if own:
        db = SessionLocal()
    global _state
    try:
        with _state_lock:
            if _state is None:
                _state = _load_state(db)
            prev_hash = _state["last_hash"]
            seq = _state["count"] + 1
            ts = datetime.now(timezone.utc).isoformat()
            entry = {
                "seq": seq,
                "ts": ts,
                "action": action,
                "actor": actor,
                "details": details or {},
                "prev_hash": prev_hash or "",
            }
            entry_hash = hashlib.sha256(_canonical(entry).encode()).hexdigest()
            row = AuditLog(
                seq=seq,
                ts=ts,
                action=action,
                actor=actor,
                details=entry["details"],
                prev_hash=entry["prev_hash"],
                entry_hash=entry_hash,
            )
            db.add(row)
            db.commit()
            db.refresh(row)
            _state = {"last_hash": row.entry_hash, "count": row.id}
            return row
    finally:
        if own:
            db.close()


def verify_chain(db: Session) -> dict:
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    prev = ""
    for row in rows:
        entry = {
            "seq": row.seq,
            "ts": row.ts,
            "action": row.action,
            "actor": row.actor,
            "details": row.details,
            "prev_hash": row.prev_hash,
        }
        expected = hashlib.sha256(_canonical(entry).encode()).hexdigest()
        if row.prev_hash != prev or expected != row.entry_hash:
            return {"valid": False, "broken_at_seq": row.seq, "entries": len(rows)}
        prev = row.entry_hash
    return {"valid": True, "entries": len(rows)}


def audit_worker_health() -> dict:
    try:
        db = SessionLocal()
        from app.models.audit import AuditLog

        total = db.query(AuditLog).count()
        db.close()
        return {"status": "ok", "entries": total}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:200]}