from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Indicator(Base):
    """A threat-intelligence indicator (STIX 2.1 aligned subset, Part 7).

    Every indicator carries its provenance: source, collection timestamp, confidence,
    validity window, context and attribution reliability — untrusted public feeds never
    get automatic authority (see engine `check`).
    """

    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    type: Mapped[str] = mapped_column(String(24), index=True)  # ipv4|domain|url|sha256|md5|email
    value: Mapped[str] = mapped_column(String(1024), index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    source_type: Mapped[str] = mapped_column(String(24), default="feed")  # feed|manual|internal
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0..100
    reliability: Mapped[str] = mapped_column(String(8), default="C")  # A..F (admiralty-style)
    added_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    context: Mapped[str] = mapped_column(String(1024), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    times_observed: Mapped[int] = mapped_column(Integer, default=0)
    labels: Mapped[list] = mapped_column(JSON, default=list)  # STIX labels if present
    raw: Mapped[dict] = mapped_column(JSON, default=dict)

    def status(self, now: datetime | None = None) -> str:
        """Indicator lifecycle honesty: active | expired | future."""
        now = (now or datetime.now(timezone.utc)).replace(tzinfo=None)
        valid_from = self.valid_from.replace(tzinfo=None) if self.valid_from else None
        valid_until = self.valid_until.replace(tzinfo=None) if self.valid_until else None
        if valid_from is not None and valid_from > now:
            return "future"
        if valid_until is not None and valid_until < now:
            return "expired"
        return "active"