from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class MediaAnalysis(Base):
    """A stored media analysis result. Raw bytes are NOT retained (ADR-011)."""

    __tablename__ = "media_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    kind: Mapped[str] = mapped_column(String(32), index=True)  # image/audio/video/document
    filename: Mapped[str] = mapped_column(String(255), default="")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    md5: Mapped[str] = mapped_column(String(32))
    size: Mapped[int] = mapped_column(default=0)
    mime: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32), default="analyzed", index=True)  # analyzed|unsupported
    risk_score: Mapped[float] = mapped_column(default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), default="clean", index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    submitted_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
