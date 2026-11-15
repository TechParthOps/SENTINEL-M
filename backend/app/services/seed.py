"""Initial data seeding: first administrator + clearly-labeled sample inventory.

Sample assets carry `sample=True` so the UI can label them honestly as examples —
they are NOT live systems and never appear as monitored assets without the badge
(ADR-008). No security events are ever fabricated.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.user import User
from app.models.asset import Asset

log = logging.getLogger("sentinel.seed")

SAMPLE_ASSETS = [
    {"hostname": "dc-01", "display_name": "Core Domain Controller", "asset_type": "domain_controller", "criticality": 5},
    {"hostname": "srv-app-01", "display_name": "Primary Application Server", "asset_type": "server", "criticality": 4},
    {"hostname": "srv-db-01", "display_name": "Customer Database", "asset_type": "database", "criticality": 5},
    {"hostname": "fw-edge-01", "display_name": "Edge Firewall", "asset_type": "firewall", "criticality": 5},
    {"hostname": "ws-eng-07", "display_name": "Engineering Workstation", "asset_type": "workstation", "criticality": 3},
    {"hostname": "cloud-app-01", "display_name": "Cloud Workload (IaaS)", "asset_type": "cloud_workload", "criticality": 4},
]


def seed_if_empty(db: Session | None = None) -> str:
    """Idempotent. Returns a human message describing what happened.

    First-launch behavior: if no seed admin password is configured the platform
    does NOT invent credentials — the first account (administrator or normal
    user) is created by the operator in the web UI (see GET /auth/bootstrap-status).
    Headless/CLI setups can still set SENTINEL_SEED_ADMIN_PASSWORD to bootstrap
    an admin automatically.
    """
    own = db is None
    if own:
        db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return "already initialized"
        if settings.seed_admin_password:
            db.add(
                User(
                    username="admin",
                    password_hash=hash_password(settings.seed_admin_password),
                    display_name="Administrator",
                    role="admin",
                    must_change_password=True,
                )
            )
            for asset in SAMPLE_ASSETS:
                db.add(Asset(**asset, sample=True))
            db.commit()
            return "initialized (admin seeded, sample inventory loaded)"
        # no seed password: leave users empty so the UI offers account creation
        for asset in SAMPLE_ASSETS:
            db.add(Asset(**asset, sample=True))
        db.commit()
        log.info("No seed admin password configured - first account is created in the UI")
        return "bootstrap (sample inventory loaded; first account via UI)"
    finally:
        if own:
            db.close()