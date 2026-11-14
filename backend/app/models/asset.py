from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Asset(Base):
    """Inventory item. `sample=True` assets are seeded examples, not live telemetry (ADR-008)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    asset_type: Mapped[str] = mapped_column(String(32), default="unknown")  # workstation|server|...
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    os: Mapped[str] = mapped_column(String(64), default="")
    owner: Mapped[str] = mapped_column(String(128), default="")
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1..5
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)  # response engine flag
    auto_registered: Mapped[bool] = mapped_column(Boolean, default=False)
    sample: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)