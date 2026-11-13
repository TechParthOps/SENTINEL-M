"""System endpoints: health registry, audit log, capability coverage."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.health import registry
from app.core.security import AdminUser, CurrentUser
from app.models.audit import AuditLog
from app.detection.engine import detection_engine, RULES_DIR
from app.core.bus import bus

router = APIRouter(prefix="", tags=["system"])

_COVERAGE_PATH = Path(__file__).resolve().parents[1] / "coverage.json"


@router.get("/health")
def health(user: CurrentUser):
    return registry.check()


@router.get("/audit", response_model=dict)
def audit_log(admin: AdminUser, db: Session = Depends(get_db), limit: int = Query(100, ge=1, le=1000)):
    rows = db.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).scalars().all()
    chain = audit.verify_chain(db)
    entries = [
        {
            "seq": r.seq,
            "ts": r.ts,
            "action": r.action,
            "actor": r.actor,
            "details": r.details,
            "prev_hash": r.prev_hash,
            "entry_hash": r.entry_hash,
        }
        for r in rows
    ]
    # reading the audit trail is itself audited (recorded after the snapshot)
    try:
        audit.record("audit.read", actor=admin.username, details={"returned": len(entries)})
    except Exception:
        pass
    return {"entries": entries, "chain": chain}


@router.get("/coverage")
def coverage(user: CurrentUser):
    """Milestone/capability coverage — mirrors research/THREAT_COVERAGE_MATRIX.md."""
    with open(_COVERAGE_PATH, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return {
        "phases": data["phases"],
        "runtime": {
            "rules_loaded": len(detection_engine.rules),
            "rules_dir": str(RULES_DIR),
            "bus": bus.stats(),
        },
    }


@router.get("/system/info")
def system_info(user: CurrentUser):
    from app.core.config import settings

    return {
        "name": settings.app_name,
        "version": settings.version,
        "environment": settings.environment,
        "secret_key_is_insecure": settings.secret_key_is_insecure,
        "modules": registry.names(),
        "rules": {"total": len(detection_engine.rules), "dir": str(RULES_DIR)},
    }