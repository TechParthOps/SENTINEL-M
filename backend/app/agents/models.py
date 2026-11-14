from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Investigation(Base):
    """An autonomous investigation run over an alert or entity."""

    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    subject_type: Mapped[str] = mapped_column(String(16), index=True)  # alert | entity
    subject_id: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # queued|running|completed|failed
    verdict: Mapped[str] = mapped_column(String(16), default="unknown", index=True)  # benign|suspicious|malicious|unknown
    summary: Mapped[str] = mapped_column(String(2048), default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(String(512), default="")
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentTask(Base):
    """One specialist-agent step inside an investigation."""

    __tablename__ = "agent_tasks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    agent: Mapped[str] = mapped_column(String(64))  # specialist role name
    description: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)  # completed|failed|skipped
    output: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(String(512), default="")
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())


class Evidence(Base):
    """Evidence with per-investigation hash chain (chain of custody)."""

    __tablename__ = "agent_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    investigation_id: Mapped[str] = mapped_column(String(36), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    kind: Mapped[str] = mapped_column(String(32))  # event|alert|incident|intel|asset
    ref_id: Mapped[str] = mapped_column(String(255))
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    sha256: Mapped[str] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())
