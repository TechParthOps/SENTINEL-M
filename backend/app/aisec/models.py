from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AiAnalysis(Base):
    """A stored AI-security text analysis. Deterministic heuristics only — never
    a verdict about a human or a model identity."""

    __tablename__ = "ai_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    kind: Mapped[str] = mapped_column(String(32), index=True)  # analysis context
    label: Mapped[str] = mapped_column(String(255), default="")
    text_sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(default=0)
    risk_score: Mapped[float] = mapped_column(default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), default="clean", index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    submitted_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
