"""SENTINEL-M FastAPI application entry point (ADR-001)."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app import api
from app.agents.engine import orchestrator
from app.aisec.engine import aisec_engine
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.health import registry
from app.core import audit
from app.core.bus import bus
from app.deception.engine import deception_engine
from app.detection.engine import detection_engine
from app.identity.engine import identity_engine
from app.intelligence.engine import intelligence_engine
from app.intelligence.models import Indicator
from app.malware.models import SampleAnalysis
from app.multimodal.models import MediaAnalysis
from app.response.engine import response_engine
from app.services.seed import seed_if_empty

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("sentinel.main")


def _db_check() -> dict:
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "url": settings.db_url.split(":///")[0]}
    except Exception as exc:
        return {"status": "error", "detail": str(exc)[:200]}
    finally:
        db.close()


def _ingestion_check() -> dict:
    return {
        "status": "ok",
        "classes": ["auth", "process", "network", "dns", "file", "http", "generic"],
    }


def _correlation_check() -> dict:
    db = SessionLocal()
    try:
        from app.models.incident import Incident

        open_incidents = db.query(Incident).filter(Incident.status == "open").count()
        return {"status": "ok", "open_incidents": open_incidents}
    finally:
        db.close()


def _malware_check() -> dict:
    from app.malware.engine import engine_health

    return engine_health()


def _aisec_check() -> dict:
    return aisec_engine.health()


def _multimodal_check() -> dict:
    from app.multimodal.engine import multimodal_engine

    return multimodal_engine.health()


def _agents_check() -> dict:
    return orchestrator.health()


def _run_migrations() -> list[str]:
    """Lightweight additive migrations for pre-Phase-5/7 SQLite databases.

    create_all() only creates MISSING tables; it never ALTERs existing ones. These
    additive column migrations keep existing dev/prod DBs (and their data) intact.
    """
    applied: list[str] = []
    with engine.connect() as conn:
        cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(assets)")]
        if cols and "isolated" not in cols:
            conn.exec_driver_sql(
                "ALTER TABLE assets ADD COLUMN isolated BOOLEAN NOT NULL DEFAULT 0"
            )
            applied.append("assets.isolated")
        user_cols = [r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)")]
        if user_cols:
            for col, ddl in (
                ("mfa_secret", "ALTER TABLE users ADD COLUMN mfa_secret VARCHAR(64)"),
                ("mfa_enabled", "ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0"),
                ("mfa_recovery", "ALTER TABLE users ADD COLUMN mfa_recovery VARCHAR(1024)"),
                ("mfa_enrolled_at", "ALTER TABLE users ADD COLUMN mfa_enrolled_at DATETIME"),
            ):
                if col not in user_cols:
                    conn.exec_driver_sql(ddl)
                    applied.append(f"users.{col}")
        conn.commit()
    return applied


@asynccontextmanager
async def lifespan(app: FastAPI):
    bus.set_loop(asyncio.get_running_loop())
    migrated = _run_migrations()
    Base.metadata.create_all(bind=engine)
    seeded = seed_if_empty()
    log.info("SENTINEL-M %s started (%s). Seeding: %s", settings.version, settings.environment, seeded)
    if migrated:
        log.info("Applied additive migrations: %s", migrated)
    if settings.secret_key_is_insecure:
        log.warning("SECRET_KEY is insecure/default — set SENTINEL_SECRET_KEY before real use!")

    registry.register("database", _db_check)
    registry.register("ingestion", _ingestion_check)
    registry.register("detection", detection_engine.health)
    registry.register("correlation", _correlation_check)
    registry.register("event_bus", lambda: {"status": "ok", **bus.stats()})
    registry.register("audit_log", audit.audit_worker_health)
    registry.register("identity", identity_engine.health)
    registry.register("intelligence", lambda: {"status": "ok", **intelligence_engine.feed_status(SessionLocal())})
    registry.register("malware", _malware_check)
    registry.register("ai_security", _aisec_check)
    registry.register("multimodal", _multimodal_check)
    registry.register("agents", _agents_check)
    registry.register("response", response_engine.health)
    registry.register("deception", deception_engine.health)

    # Phase 2: auto-load local STIX feeds on startup (offline-first)
    intel_stats = intelligence_engine.load_feeds(SessionLocal())
    log.info("Threat intel feeds: %s", intel_stats)

    yield
    deception_engine.stop_all(SessionLocal())  # safe termination of listeners
    bus.set_loop(None)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description="Autonomous Multimodal Cyber Defense Platform — Phase 1 Core API",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api.auth.router, prefix="/api/v1")
    app.include_router(api.events.router, prefix="/api/v1")
    app.include_router(api.assets.router, prefix="/api/v1")
    app.include_router(api.alerts.router, prefix="/api/v1")
    app.include_router(api.incidents.router, prefix="/api/v1")
    app.include_router(api.identity.router, prefix="/api/v1")
    app.include_router(api.rules.router, prefix="/api/v1")
    app.include_router(api.intelligence.router, prefix="/api/v1")
    app.include_router(api.malware.router, prefix="/api/v1")
    app.include_router(api.aisec.router, prefix="/api/v1")
    app.include_router(api.multimodal.router, prefix="/api/v1")
    app.include_router(api.agents.router, prefix="/api/v1")
    app.include_router(api.hunt.router, prefix="/api/v1")
    app.include_router(api.response.router, prefix="/api/v1")
    app.include_router(api.deception.router, prefix="/api/v1")
    app.include_router(api.stats.router, prefix="/api/v1")
    app.include_router(api.system.router, prefix="/api/v1")
    app.include_router(api.ws.router)

    @app.get("/api/v1", tags=["meta"])
    def root() -> dict:
        return {"name": settings.app_name, "version": settings.version, "status": "running"}

    return app


app = create_app()