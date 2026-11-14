"""Multimodal analysis API: in-memory media analysis, no byte retention."""
from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser
from app.multimodal.engine import multimodal_engine

router = APIRouter(prefix="/media", tags=["multimodal"])

MAX_MEDIA_BYTES = 20 * 1024 * 1024  # 20 MB analysis cap


class SubmitRequest(BaseModel):
    filename: str = ""
    content_base64: str = ""


@router.post("/analyze")
def analyze_media(payload: SubmitRequest, user: AnalystUser, db: Session = Depends(get_db)):
    if not payload.content_base64:
        raise HTTPException(422, "content_base64 required")
    try:
        raw = base64.b64decode(payload.content_base64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, "content_base64 is not valid base64") from None
    if not raw:
        raise HTTPException(422, "empty file")
    if len(raw) > MAX_MEDIA_BYTES:
        raise HTTPException(413, f"file exceeds {MAX_MEDIA_BYTES // (1024 * 1024)} MB analysis cap")
    result = multimodal_engine.analyze(raw, filename=payload.filename or "")
    row = multimodal_engine.save(db, result, actor=user.username)
    audit.record("media.analyzed", actor=user.username,
                 details={"kind": result.get("kind"), "status": result.get("status"),
                          "verdict": result["verdict"], "sha256": result["sha256"]})
    return result


@router.get("/analyses")
def list_analyses(user: CurrentUser, db: Session = Depends(get_db),
                  limit: int = Query(100, ge=1, le=500)):
    return {"total": len(multimodal_engine.list_analyses(db, limit)),
            "analyses": multimodal_engine.list_analyses(db, limit)}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, user: CurrentUser, db: Session = Depends(get_db)):
    for a in multimodal_engine.list_analyses(db, 500):
        if a["id"] == analysis_id:
            return a
    raise HTTPException(404, "analysis not found")
