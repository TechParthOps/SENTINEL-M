"""Threat hunting API: query events/alerts by IOC, entity, class and time range.

Read-only hunting over the retained event/alert stores. SQLite JSON columns are queried
in Python after a bounded SQL pre-filter — deliberate for the local-first single-node
deployment (documented performance trade-off).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import AnalystUser
from app.models.alert import Alert
from app.models.event import Event
from app.schemas import EventOut

router = APIRouter(prefix="/hunt", tags=["hunt"])


@router.get("")
def hunt(
    user: AnalystUser,
    db: Session = Depends(get_db),
    q: str | None = Query(None, max_length=255,
                          description="free-text or IOC value (matched in observables, message, src/dst IP, host)"),
    class_name: str | None = None,
    host: str | None = None,
    hours: int = Query(168, ge=1, le=24 * 90, description="lookback window in hours"),
    limit: int = Query(200, ge=1, le=1000),
):
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)

    stmt = select(Event).where(Event.time >= since).order_by(Event.time.desc()).limit(5000)
    if class_name:
        stmt = stmt.where(Event.class_name == class_name)
    if host:
        stmt = stmt.where(Event.host == host)
    rows = db.execute(stmt).scalars().all()

    needle = (q or "").lower()
    matched: list[Event] = []
    for ev in rows:
        if not needle:
            matched = list(rows)
            break
        in_observables = any(needle in str(o.get("value", "")).lower()
                             for o in (ev.observables or []))
        if (in_observables
                or needle in (ev.message or "").lower()
                or needle in (ev.src_ip or "")
                or needle in (ev.dst_ip or "")
                or needle in (ev.host or "")
                or needle in (ev.user or "")):
            matched.append(ev)
        if len(matched) >= limit:
            break

    alert_stmt = select(Alert).where(Alert.time >= since).order_by(Alert.time.desc()).limit(1000)
    alert_rows = db.execute(alert_stmt).scalars().all()
    alerts_hit = [
        a for a in alert_rows
        if not needle
        or needle in (a.entity_key or "").lower()
        or needle in (a.rule_id or "").lower()
        or needle in (a.message or "").lower()
    ][:100]

    return {
        "query": {"q": q, "class_name": class_name, "host": host, "hours": hours},
        "total_events": len(matched),
        "events": [EventOut.model_validate(e).model_dump() for e in matched[:limit]],
        "total_alerts": len(alerts_hit),
        "alerts": [
            {
                "id": a.id, "time": a.time.isoformat() if a.time else None,
                "rule_id": a.rule_id, "rule_title": a.rule_title,
                "severity_id": a.severity_id, "entity_key": a.entity_key,
                "attack_ids": a.attack_ids or [], "status": a.status,
                "incident_id": a.incident_id, "message": a.message,
            }
            for a in alerts_hit
        ],
    }
