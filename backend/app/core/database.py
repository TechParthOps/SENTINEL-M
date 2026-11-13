"""Database engine/session (ADR-009: SQLite WAL for Phase 1, PostgreSQL target later)."""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.engine import Engine

from app.core.config import settings


class Base(DeclarativeBase):
    pass


_is_sqlite = settings.db_url.startswith("sqlite")
engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
    pool_pre_ping=True,
    echo=False,
)


if _is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=3000")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()