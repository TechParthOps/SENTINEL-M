"""Detection rule registry API (loaded JSON rules, ADR-005)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.security import CurrentUser
from app.detection.engine import detection_engine

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("", response_model=dict)
def list_rules(user: CurrentUser):
    rules = detection_engine.rules_public()
    return {"total": len(rules), "rules": rules}


@router.get("/{rule_id}")
def rule_detail(rule_id: str, user: CurrentUser):
    for rule in detection_engine.rules_public():
        if rule["id"] == rule_id:
            return rule
    from fastapi import HTTPException

    raise HTTPException(404, "rule not found")