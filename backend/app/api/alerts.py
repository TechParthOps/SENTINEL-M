"""Alert management API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser
from app.models.alert import Alert
from app.schemas import AlertOut, AlertPatch

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=dict)
def list_alerts(
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(200, ge=1, le=2000),
    status: str | None = None,
    severity_gte: int | None = Query(None, ge=0, le=6),
):
    stmt = select(Alert).order_by(Alert.time.desc())
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity_gte is not None:
        stmt = stmt.where(Alert.severity_id >= severity_gte)
    total = db.query(Alert).count()
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return {"total": total, "alerts": [AlertOut.model_validate(a).model_dump() for a in rows]}


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    return alert


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(payload: AlertPatch, alert_id: str, user: AnalystUser, db: Session = Depends(get_db)):
    """Analyst+ workflow state changes (viewer role is rejected with 403)."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(404, "alert not found")
    previous = alert.status
    alert.status = payload.status
    db.commit()
    db.refresh(alert)
    audit.record(
        "alert.update",
        actor=user.username,
        details={"alert_id": alert_id, "from": previous, "to": payload.status},
    )
    return alert