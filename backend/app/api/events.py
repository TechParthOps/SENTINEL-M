"""Event ingestion & query API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import settings
from app.core.database import get_db
from app.core.ratelimit import check_rate_limit
from app.core.security import AnalystUser, CurrentUser
from app.ingestion.gateway import ingest_events
from app.models.event import Event
from app.schemas import EventOut, IngestRequest

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest")
def ingest(payload: IngestRequest, request: Request, user: CurrentUser, db: Session = Depends(get_db)):
    """Authenticated ingestion. Rate-limited. Every batch is audit-recorded."""
    check_rate_limit(request, "events.ingest", settings.ingest_ratelimit_per_min)
    return ingest_events(db, payload, actor=user.username)


@router.get("", response_model=dict)
def list_events(
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    class_name: str | None = None,
    host: str | None = None,
    src_ip: str | None = None,
    search: str | None = Query(None, max_length=255),
):
    stmt = select(Event).order_by(Event.time.desc())
    if class_name:
        stmt = stmt.where(Event.class_name == class_name)
    if host:
        stmt = stmt.where(Event.host == host)
    if src_ip:
        stmt = stmt.where(Event.src_ip == src_ip)
    if search:
        stmt = stmt.where(Event.message.contains(search))
    total = db.query(Event).count()
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return {"total": total, "events": [EventOut.model_validate(e).model_dump() for e in rows]}