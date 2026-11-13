from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Event(Base):
    """Normalized security event (OCSF-aligned subset, ADR-004)."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    event_uid: Mapped[str] = mapped_column(String(128), default="")  # vendor event id
    time: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    class_uid: Mapped[str] = mapped_column(String(8), index=True)
    class_name: Mapped[str] = mapped_column(String(48), index=True)
    severity_id: Mapped[int] = mapped_column(Integer, default=1)
    message: Mapped[str] = mapped_column(String(1024), default="")

    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    source_product: Mapped[str] = mapped_column(String(64), default="")
    source_version: Mapped[str] = mapped_column(String(32), default="")

    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    observables: Mapped[list] = mapped_column(JSON, default=list)
    enriched: Mapped[dict] = mapped_column(JSON, default=dict)  # Phase 2+: TI enrichment