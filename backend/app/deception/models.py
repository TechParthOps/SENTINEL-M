from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Honeypot(Base):
    """A deception asset. Decoy credentials are generated randomly at creation and are
    NEVER sourced from the real identity inventory."""

    __tablename__ = "honeypots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid
    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # http_login|tcp_banner|canary_token
    port: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(16), default="stopped", index=True)  # running|stopped
    decoy_identity: Mapped[str] = mapped_column(String(64), default="")  # decoy USERNAME only
    decoy_secret_sha256: Mapped[str] = mapped_column(String(64), default="")  # hash, not plaintext
    canary_path: Mapped[str] = mapped_column(String(128), default="")
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    interactions_count: Mapped[int] = mapped_column(Integer, default=0)
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow())


class HoneypotInteraction(Base):
    """One attacker interaction with a deception asset."""

    __tablename__ = "honeypot_interactions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    honeypot_id: Mapped[str] = mapped_column(String(36), index=True)
    time: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.utcnow(), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), default="")
    kind: Mapped[str] = mapped_column(String(32), default="")  # tcp_connect|login_attempt|canary_hit
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
