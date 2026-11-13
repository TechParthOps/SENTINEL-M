from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Alert(Base):
    """A detection finding produced by a deterministic rule (ADR-005)."""

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    time: Mapped[datetime] = mapped_column(DateTime, index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_title: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(64), default="security_finding")
    severity_id: Mapped[int] = mapped_column(Integer, default=3)  # OCSF severity 0..6
    entity_key: Mapped[str] = mapped_column(String(255), index=True)
    entity_type: Mapped[str] = mapped_column(String(16), default="host")
    attack_ids: Mapped[list] = mapped_column(JSON, default=list)
    attack_tactics: Mapped[list] = mapped_column(JSON, default=list)
    evidence_event_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(16), default="new")
    message: Mapped[str] = mapped_column(String(1024), default="")
    source_product: Mapped[str] = mapped_column(String(64), default="")
    incident_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    dedup_sig: Mapped[str] = mapped_column(String(64), default="", index=True)