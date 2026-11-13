from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Incident(Base):
    """Correlated group of alerts forming an investigation unit (ADR-006)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(String(2048), default="")
    category: Mapped[str] = mapped_column(String(64), default="security_finding")
    severity_id: Mapped[int] = mapped_column(Integer, default=3)
    entity_keys: Mapped[list] = mapped_column(JSON, default=list)
    attack_ids: Mapped[list] = mapped_column(JSON, default=list)
    attack_chain: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    analyst_notes: Mapped[str] = mapped_column(String(4096), default="")
    source_products: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )