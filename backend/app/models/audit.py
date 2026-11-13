from __future__ import annotations

from sqlalchemy import Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    ts: Mapped[str] = mapped_column(String(40))
    action: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(128), default="system")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    entry_hash: Mapped[str] = mapped_column(String(64), index=True)