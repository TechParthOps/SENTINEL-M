"""Threat intelligence API: indicator registry, feed control, lookup."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AdminUser, CurrentUser
from app.intelligence.engine import FEEDS_DIR, intelligence_engine
from app.intelligence.models import Indicator
from app.intelligence.stix import parse_bundle

router = APIRouter(prefix="/intel", tags=["intelligence"])


def _out(i: Indicator) -> dict:
    return {
        "id": i.id,
        "type": i.type,
        "value": i.value,
        "source": i.source,
        "source_type": i.source_type,
        "confidence": i.confidence,
        "reliability": i.reliability,
        "status": i.status(),
        "valid_from": i.valid_from.isoformat() if i.valid_from else None,
        "valid_until": i.valid_until.isoformat() if i.valid_until else None,
        "added_at": i.added_at.isoformat() if i.added_at else None,
        "tags": i.tags or [],
        "times_observed": i.times_observed or 0,
        "last_seen": i.last_seen.isoformat() if i.last_seen else None,
        "context": i.context,
    }


@router.get("/indicators")
def list_indicators(
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=2000),
    ioc_type: str | None = None,
    status: str | None = Query(None, pattern="^(active|expired|future)$"),
    search: str | None = Query(None, max_length=255),
    source: str | None = None,
):
    stmt = select(Indicator).order_by(Indicator.added_at.desc())
    if ioc_type:
        stmt = stmt.where(Indicator.type == ioc_type)
    if source:
        stmt = stmt.where(Indicator.source == source)
    rows = db.execute(stmt.limit(limit * 3)).scalars().all()
    if status:
        rows = [r for r in rows if r.status() == status]
    if search:
        needle = search.lower()
        rows = [r for r in rows if needle in r.value.lower()]
    total = len(rows)
    return {"total": total, "indicators": [_out(r) for r in rows[:limit]]}


@router.get("/lookup")
def lookup(user: CurrentUser, db: Session = Depends(get_db), ioc_type: str = "ipv4", value: str = ""):
    """Safe IOC resolution: does any ACTIVE, non-expired indicator cover this value?"""
    if not value:
        raise HTTPException(422, "value required")
    rows = intelligence_engine.lookup(db, ioc_type, value, active_only=True)
    return {"matches": [_out(r) for r in rows], "count": len(rows)}


@router.get("/status")
def status(user: CurrentUser, db: Session = Depends(get_db)):
    return intelligence_engine.feed_status(db)


@router.post("/feeds/reload")
def reload_feeds(admin: AdminUser, db: Session = Depends(get_db)):
    stats = intelligence_engine.load_feeds(db)
    audit.record("intel.feed_reload", actor=admin.username, details=stats)
    return stats


@router.post("/import", status_code=201)
def import_bundle(payload: dict, admin: AdminUser, db: Session = Depends(get_db)):
    """Directly import a STIX 2.1 JSON bundle (admin). Same validation as file feeds."""
    source_name = str(payload.get("x_source", "manual-import"))[:64]
    try:
        indicators = parse_bundle(payload, default_source=source_name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    result = intelligence_engine.import_indicators(db, indicators)
    audit.record(
        "intel.import", actor=admin.username,
        details={"source": source_name, **result},
    )
    return {"source": source_name, **result}


@router.get("/feeds")
def feeds(user: CurrentUser):
    files = sorted(p.stem for p in FEEDS_DIR.glob("*.json")) if FEEDS_DIR.is_dir() else []
    return {"feeds_dir": str(FEEDS_DIR), "feeds": files}