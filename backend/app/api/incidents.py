"""Incident API: list, evidence-backed detail, analyst workflow."""
from __future__ import annotations

import datetime as dt
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser
from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas import AlertOut, IncidentDetailOut, IncidentOut, IncidentPatch

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=dict)
def list_incidents(
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    status: str | None = None,
    severity_gte: int | None = Query(None, ge=0, le=6),
):
    stmt = select(Incident).order_by(Incident.last_seen.desc())
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity_gte is not None:
        stmt = stmt.where(Incident.severity_id >= severity_gte)
    total = db.query(Incident).count()
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return {"total": total, "incidents": [IncidentOut.model_validate(i).model_dump() for i in rows]}


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def incident_detail(incident_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "incident not found")
    alerts = (
        db.execute(select(Alert).where(Alert.id.in_(incident.alert_ids or [])).order_by(Alert.time))
        .scalars()
        .all()
    )
    detail = IncidentDetailOut.model_validate(incident).model_dump()
    detail["alerts"] = [
        AlertOut.model_validate(a).model_dump() for a in alerts
    ]
    audit.record("incident.view", actor=user.username, details={"incident_id": incident_id})
    return detail


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    payload: IncidentPatch,
    incident_id: str,
    user: AnalystUser,
    db: Session = Depends(get_db),
):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "incident not found")
    changes: dict = {}
    if payload.status:
        changes["status"] = f"{incident.status}->{payload.status}"
        incident.status = payload.status
    if payload.analyst_notes is not None:
        changes["notes_chars"] = len(payload.analyst_notes)
        incident.analyst_notes = payload.analyst_notes
    incident.updated_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    db.refresh(incident)
    audit.record(
        "incident.update", actor=user.username, details={"incident_id": incident_id, **changes}
    )
    return incident