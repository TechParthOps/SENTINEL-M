"""AI-security API: text analysis + stored analyses list."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.aisec.engine import aisec_engine
from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser

router = APIRouter(prefix="/aisec", tags=["ai-security"])

CONTEXTS = ("prompt", "chat", "document", "web", "email", "rag", "llm_output")


class TextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=200_000)
    context: str = Field(default="prompt")
    label: str = Field(default="", max_length=255)


@router.post("/analyze-text")
def analyze_text(payload: TextRequest, user: AnalystUser, db: Session = Depends(get_db)):
    if payload.context not in CONTEXTS:
        raise HTTPException(422, f"context must be one of {CONTEXTS}")
    result = aisec_engine.analyze(payload.text, payload.context)
    row = aisec_engine.save(db, result, payload.context, payload.label, actor=user.username)
    audit.record("aisec.text_analyzed", actor=user.username,
                 details={"context": payload.context, "verdict": result["verdict"],
                          "risk_score": result["risk_score"], "sha256": result["text_sha256"]})
    return result


@router.get("/analyses")
def list_analyses(user: CurrentUser, db: Session = Depends(get_db),
                  limit: int = Query(100, ge=1, le=500)):
    return {"total": len(aisec_engine.list_analyses(db, limit)),
            "analyses": aisec_engine.list_analyses(db, limit)}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    for a in aisec_engine.list_analyses(db, 500):
        if a["id"] == analysis_id:
            return a
    raise HTTPException(404, "analysis not found")
