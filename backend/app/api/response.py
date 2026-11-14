"""Response API: policy view, request/dry-run/approve/execute/rollback/deny, denylist."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AdminUser, AnalystUser, CurrentUser
from app.response.engine import response_engine
from app.response.models import ResponseAction

router = APIRouter(prefix="/response", tags=["response"])


class ActionRequest(BaseModel):
    action_type: str = Field(min_length=3, max_length=64)
    target_type: str = Field(pattern="^(asset|ip|alert|incident)$")
    target: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=3, max_length=1024)
    dry_run: bool = False


def _action(db: Session, action_id: str) -> ResponseAction:
    row = db.get(ResponseAction, action_id)
    if row is None:
        raise HTTPException(404, "action not found")
    return row


def _pub(a: ResponseAction) -> dict:
    return {
        "id": a.id, "action_type": a.action_type, "target_type": a.target_type,
        "target": a.target, "reason": a.reason, "status": a.status, "dry_run": a.dry_run,
        "requested_by": a.requested_by, "approved_by": a.approved_by,
        "result": a.result, "verification": a.verification,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "executed_at": a.executed_at.isoformat() if a.executed_at else None,
    }


@router.get("/policy")
def policy(user: CurrentUser):
    return response_engine.policy()


@router.post("/actions", status_code=201)
def request_action(payload: ActionRequest, user: AnalystUser, db: Session = Depends(get_db)):
    try:
        action = response_engine.request(db, payload.action_type, payload.target_type,
                                         payload.target, payload.reason, actor=user.username,
                                         dry_run=payload.dry_run)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit.record("response.requested", actor=user.username,
                 details={"action_id": action.id, "type": action.action_type, "dry_run": action.dry_run})
    if action.dry_run:
        try:
            action = response_engine.dry_run(db, action)
        except PermissionError as exc:
            raise HTTPException(403, str(exc)) from None
    else:
        # autonomy: L2 reversible actions on non-critical targets auto-execute (policy-gated)
        decision = response_engine.decide(db, action.action_type, action.target_type,
                                          action.target, dry_run=False)
        if decision.allowed and not decision.requires_approval:
            action = response_engine.execute(db, action, actor=user.username)
        elif not decision.allowed:
            action = response_engine.deny(db, action, user.username, decision.reason)
    return _pub(action)


@router.post("/actions/{action_id}/approve")
def approve(action_id: str, user: AdminUser, db: Session = Depends(get_db)):
    try:
        action = response_engine.approve(db, _action(db, action_id), user.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _pub(action)


@router.post("/actions/{action_id}/deny")
def deny(action_id: str, user: AdminUser, db: Session = Depends(get_db),
         reason: str = Query("denied by operator", max_length=512)):
    action = response_engine.deny(db, _action(db, action_id), user.username, reason)
    return _pub(action)


@router.post("/actions/{action_id}/execute")
def execute(action_id: str, user: AnalystUser, db: Session = Depends(get_db)):
    try:
        action = response_engine.execute(db, _action(db, action_id), user.username)
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _pub(action)


@router.post("/actions/{action_id}/rollback")
def rollback(action_id: str, user: AdminUser, db: Session = Depends(get_db)):
    try:
        action = response_engine.rollback(db, _action(db, action_id), user.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _pub(action)


@router.post("/actions/{action_id}/verify")
def verify(action_id: str, user: AnalystUser, db: Session = Depends(get_db)):
    action = _action(db, action_id)
    return response_engine.verify(db, action)


@router.get("/actions")
def list_actions(user: CurrentUser, db: Session = Depends(get_db),
                 limit: int = Query(100, ge=1, le=500)):
    rows = response_engine.list_actions(db, limit)
    return {"total": len(rows), "actions": rows}


@router.get("/denylist")
def denylist(user: CurrentUser, db: Session = Depends(get_db)):
    return {"entries": response_engine.denylist(db)}
