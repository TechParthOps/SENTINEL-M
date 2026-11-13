"""SENTINEL-M FastAPI application entry point (ADR-001)."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app import api
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.health import registry
from app.core import audit
from app.core.bus import bus
from app.detection.engine import detection_engine
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
    return {"status": "ok", "classes": ["auth", "process", "network", "dns", "file", "http", "+generic"]}


def _correlation_check() -> dict:
    db = SessionLocal()
    try:
        from app.models.incident import Incident

        open_incidents = db.query(Incident).filter(Incident.status == "open").count()
        return {"status": "ok", "open_incidents": open_incidents}
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    bus.set_loop(asyncio.get_running_loop())
    Base.metadata.create_all(bind=engine)
    seeded = seed_if_empty()
    log.info("SENTINEL-M %s started (%s). Seeding: %s", settings.version, settings.environment, seeded)
    if settings.secret_key_is_insecure:
        log.warning("SECRET_KEY is insecure/default — set SENTINEL_SECRET_KEY before real use!")

    registry.register("database", _db_check)
    registry.register("ingestion", _ingestion_check)
    registry.register("detection", detection_engine.health)
    registry.register("correlation", _correlation_check)
    registry.register("event_bus", lambda: {"status": "ok", **bus.stats()})
    registry.register("audit_log", audit.audit_worker_health)

    yield
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
    app.include_router(api.rules.router, prefix="/api/v1")
    app.include_router(api.stats.router, prefix="/api/v1")
    app.include_router(api.system.router, prefix="/api/v1")
    app.include_router(api.ws.router)

    @app.get("/api/v1", tags=["meta"])
    def root() -> dict:
        return {"name": settings.app_name, "version": settings.version, "status": "running"}

    return app


app = create_app()