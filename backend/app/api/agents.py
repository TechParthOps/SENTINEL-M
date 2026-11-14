"""Autonomous investigation API: start, list, inspect, evidence chain."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.agents.engine import orchestrator
from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser

router = APIRouter(prefix="/agents", tags=["agents"])


class InvestigateRequest(BaseModel):
    subject_type: str = Field(pattern="^(alert|entity)$", max_length=8)
    subject_id: str = Field(min_length=1, max_length=255)


@router.post("/investigations")
def start_investigation(payload: InvestigateRequest, user: AnalystUser, db: Session = Depends(get_db)):
    """Start an autonomous investigation. Agents are read-only; response actions are
    Phase 5 behind an approval workflow."""
    try:
        inv = orchestrator.start_investigation(db, payload.subject_type, payload.subject_id,
                                               actor=user.username)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit.record("agents.investigation_started", actor=user.username,
                 details={"investigation_id": inv.id, "subject_type": inv.subject_type,
                          "subject_id": inv.subject_id})
    inv = orchestrator.run(db, inv)
    return orchestrator.get(db, inv.id)


@router.get("/investigations")
def list_investigations(user: CurrentUser, db: Session = Depends(get_db),
                        limit: int = Query(50, ge=1, le=200)):
    rows = orchestrator.list_investigations(db, limit)
    return {"total": len(rows), "investigations": rows}


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    detail = orchestrator.get(db, inv_id)
    if detail is None:
        raise HTTPException(404, "investigation not found")
    return detail


@router.get("/investigations/{inv_id}/evidence")
def get_evidence(inv_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    ev = orchestrator.evidence(db, inv_id)
    if ev is None:
        raise HTTPException(404, "investigation not found")
    return ev
