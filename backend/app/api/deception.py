"""Deception API: honeypot lifecycle + interactions. The canary hit endpoint is
INTENTIONALLY unauthenticated (it exists to be triggered by leaked links)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AdminUser, CurrentUser
from app.deception.engine import deception_engine
from app.deception.models import Honeypot

router = APIRouter(prefix="/deception", tags=["deception"])


class PotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = Field(pattern="^(http_login|tcp_banner|canary_token)$")
    port: int = Field(default=0, ge=0, le=65535)


def _pot(db: Session, pot_id: str) -> Honeypot:
    row = db.get(Honeypot, pot_id)
    if row is None:
        raise HTTPException(404, "honeypot not found")
    return row


@router.get("/pots")
def list_pots(user: CurrentUser, db: Session = Depends(get_db)):
    return {"total": len(deception_engine.list_pots(db)), "pots": deception_engine.list_pots(db)}


@router.post("/pots", status_code=201)
def create_pot(payload: PotCreate, user: AdminUser, db: Session = Depends(get_db)):
    try:
        pot = deception_engine.create(db, payload.name, payload.kind, payload.port, user.username)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    audit.record("deception.pot_created", actor=user.username,
                 details={"honeypot_id": pot.id, "kind": pot.kind, "port": pot.port})
    return deception_engine._public(pot)  # noqa: SLF001 — module-private helper, same package boundary


@router.post("/pots/{pot_id}/start")
def start_pot(pot_id: str, user: AdminUser, db: Session = Depends(get_db)):
    try:
        pot = deception_engine.start(db, _pot(db, pot_id))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    except OSError as exc:
        raise HTTPException(409, f"listener bind failed: {exc}") from None
    audit.record("deception.pot_started", actor=user.username, details={"honeypot_id": pot.id})
    return deception_engine._public(pot)  # noqa: SLF001


@router.post("/pots/{pot_id}/stop")
def stop_pot(pot_id: str, user: AdminUser, db: Session = Depends(get_db)):
    pot = deception_engine.stop(db, _pot(db, pot_id))
    audit.record("deception.pot_stopped", actor=user.username, details={"honeypot_id": pot.id})
    return deception_engine._public(pot)  # noqa: SLF001


@router.get("/pots/{pot_id}/interactions")
def pot_interactions(pot_id: str, user: CurrentUser, db: Session = Depends(get_db),
                     limit: int = Query(100, ge=1, le=500)):
    _pot(db, pot_id)
    return {"total": len(deception_engine.interactions(db, pot_id, limit)),
            "interactions": deception_engine.interactions(db, pot_id, limit)}


@router.get("/canary/{path}")
def canary_hit(path: str, request: Request, db: Session = Depends(get_db)):
    """Public by design: any hit is a signal. Records the interaction and 200s."""
    pot = deception_engine.canary_hit(db, f"/deception/canary/{path}", request.client.host if request.client else "",
                                      {"headers": dict(list(request.headers.items())[:8])})
    if pot is None:
        raise HTTPException(404, "not found")
    return {"recorded": True, "decoy": pot.name}
