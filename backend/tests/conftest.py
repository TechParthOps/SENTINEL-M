"""Pytest configuration: environment must be set before app modules import."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

_TMP = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ["SENTINEL_DB_URL"] = f"sqlite:///{Path(_TMP).as_posix()}/test.db"
os.environ["SENTINEL_DATA_DIR"] = _TMP
os.environ["SENTINEL_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["SENTINEL_SEED_ADMIN_PASSWORD"] = "TestAdmin!Pass123"
os.environ["SENTINEL_RATELIMIT_ENABLED"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ADMIN_PASSWORD = "TestAdmin!Pass123"


@pytest.fixture(scope="session")
def client():
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_token(client):
    r = client.post("/api/v1/auth/login",
                    json={"username": "admin", "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture()
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(autouse=True)
def _reset_detection_state():
    """Isolate detection/correlation state between tests.

    Engine windows, cooldowns and DB alert/incident rows are cleared so alert-count
    assertions cannot cross-contaminate. Events/assets/audit persist (session-scoped
    stats and audit-chain tests depend on accumulated state).
    """
    from app.detection.engine import detection_engine
    from app.core.database import SessionLocal
    from app.models.alert import Alert
    from app.models.incident import Incident
    from sqlalchemy import delete

    detection_engine._window.clear()
    detection_engine._last_alert.clear()
    detection_engine._last_sig.clear()
    detection_engine.fired_counts.clear()
    db = SessionLocal()
    try:
        db.execute(delete(Alert))
        db.execute(delete(Incident))
        db.commit()
    finally:
        db.close()
    yield


def ingest(client, headers, events, source="pytest-sensor", version="1.0.0"):
    return client.post(
        "/api/v1/events/ingest", headers=headers,
        json={"source": {"product": source, "version": version}, "events": events},
    )
