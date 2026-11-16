"""Multimodal analysis API: streamed file analysis, no byte retention.

Uploads arrive as multipart/form-data and are streamed to a temporary file on
disk in fixed-size chunks (bounded memory, ANY file size), analyzed by path,
then the temporary file is deleted. Raw bytes are never persisted.
"""
from __future__ import annotations

import os
import shutil
import tempfile

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser
from app.multimodal.engine import multimodal_engine

router = APIRouter(prefix="/media", tags=["multimodal"])

_STREAM_CHUNK = 1024 * 1024


@router.post("/analyze")
def analyze_media(
    user: AnalystUser,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Stream-analyze an uploaded media/document file of any size. No size cap."""
    suffix = os.path.splitext(file.filename or "")[1] or ".bin"
    tmp_path = None
    try:
        # stream the request body to disk (never fully in memory)
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            tmp_path = tf.name
            shutil.copyfileobj(file.file, tf, length=_STREAM_CHUNK)
        if os.path.getsize(tmp_path) == 0:
            raise HTTPException(422, "empty file")
        result = multimodal_engine.analyze_path(tmp_path, filename=file.filename or "")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    row = multimodal_engine.save(db, result, actor=user.username)
    audit.record("media.analyzed", actor=user.username,
                 details={"kind": result.get("kind"), "status": result.get("status"),
                          "size": result.get("size"), "verdict": result["verdict"],
                          "sha256": result["sha256"]})
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
