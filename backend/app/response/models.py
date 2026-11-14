from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ResponseAction(Base):
    """A policy-gated response action. NO action executes without passing the policy
    engine (allowlist + autonomy level + approval or dry-run)."""

    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str] = mapped_column(String(32), default="asset")  # asset|ip|alert|incident
    target: Mapped[str] = mapped_column(String(255), index=True)
    reason: Mapped[str] = mapped_column(String(1024), default="")
    status: Mapped[str] = mapped_column(String(16), default="requested", index=True)
    # requested|approved|denied|dry_run|executed|failed|rolled_back|verified
    dry_run: Mapped[bool] = mapped_column(default=False)
    requested_by: Mapped[str] = mapped_column(String(128), default="system")
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)   # execution + previous state
    verification: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DenylistEntry(Base):
    """IP denylist produced by approved response actions. Consumers (edge/firewall
    integrations) poll this table; the platform itself does not pretend to enforce it
    beyond honest state bookkeeping."""

    __tablename__ = "response_denylist"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    ip: Mapped[str] = mapped_column(String(45), unique=True, index=True)
    added_by: Mapped[str] = mapped_column(String(128), default="system")
    reason: Mapped[str] = mapped_column(String(512), default="")
    added_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
