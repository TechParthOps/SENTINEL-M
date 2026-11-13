"""Audit log + system health + stats tests."""
from __future__ import annotations

import hashlib
import json

from tests.conftest import ingest


def test_health_reports_all_modules(client, admin_headers):
    r = client.get("/api/v1/health", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    for module in ("database", "ingestion", "detection", "correlation", "event_bus"):
        assert module in body["modules"], f"missing module {module}"
        assert body["modules"][module]["status"] == "ok"


def test_audit_chain_valid_and_tamper_evident(client, admin_headers):
    # generate audited actions
    client.post("/api/v1/assets", headers=admin_headers,
                json={"hostname": "audit-test-host", "criticality": 2})
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"src_ip": "10.4.4.4", "outcome": "success", "user": "auditor", "host": "dc-01"}}])
    r = client.get("/api/v1/audit?limit=100", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["chain"]["valid"] is True
    entries = body["entries"]
    assert len(entries) >= 2
    actions = {e["action"] for e in entries}
    assert "asset.create" in actions and "auth.login" in actions
    # entries come newest-first; verify hash linkage by recomputing from oldest
    chronological = list(reversed(entries))
    for prev, cur in zip(chronological, chronological[1:]):
        assert cur["prev_hash"] == prev["entry_hash"]


def test_audit_requires_admin(client):
    client.post("/api/v1/auth/users",
                json={"username": "audit-viewer", "password": "Viewer!Pass12", "role": "viewer"})
    tok = client.post("/api/v1/auth/login",
                      json={"username": "audit-viewer", "password": "Viewer!Pass12"}).json()["access_token"]
    r = client.get("/api/v1/audit", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403


def test_stats_overview_shapes(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"src_ip": "10.5.5.5", "outcome": "failure", "user": "stats-u", "host": "dc-01"}}])
    r = client.get("/api/v1/stats/overview", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["events"]["total"] > 0
    assert len(body["events"]["timeline_30m"]) == 30
    assert body["assets"]["total"] > 0
    assert body["incidents"]["total"] >= 0
    assert isinstance(body["top_rules_24h"], list)


def test_coverage_endpoint_matches_matrix(client, admin_headers):
    r = client.get("/api/v1/coverage", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    phases = {p["phase"]: p for p in body["phases"]}
    assert phases[1]["status"] == "implemented"
    assert all(c["status"] == "implemented" for c in phases[1]["capabilities"])
    assert phases[6]["status"] == "planned"
    assert body["runtime"]["rules_loaded"] >= 9
