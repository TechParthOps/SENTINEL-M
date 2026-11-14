"""Threat intelligence engine tests: STIX import, dedup, aging, enrichment alerts."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tests.conftest import ingest

FIXTURE_BUNDLE = {
    "type": "bundle",
    "id": "bundle--test",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--test-1",
            "pattern": "[ipv4-addr:value = '203.0.113.201']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 80,
            "x_source": "test-feed",
        },
        {
            "type": "indicator",
            "id": "indicator--test-2",
            "pattern": "[domain-name:value = 'evil.example']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
            "confidence": 70,
            "x_source": "test-feed",
        },
        {
            "type": "indicator",
            "id": "indicator--test-expired",
            "pattern": "[ipv4-addr:value = '192.0.2.199']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2024-06-01T00:00:00Z",
            "confidence": 95,
            "x_source": "test-feed",
        },
        {
            "type": "indicator",
            "id": "indicator--test-lowconf",
            "pattern": "[domain-name:value = 'sneaky.example']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00Z",
            "confidence": 30,
            "x_source": "test-feed",
        },
    ],
}


@pytest.fixture()
def intel_loaded(client, admin_headers):
    """Import the test bundle directly through the API (admin-only) and clean up after."""
    from app.core.database import SessionLocal
    from app.intelligence.models import Indicator
    from sqlalchemy import delete

    r = client.post("/api/v1/intel/import", headers=admin_headers, json=FIXTURE_BUNDLE)
    assert r.status_code == 201, r.text
    assert r.json()["imported"] == 4
    yield r.json()
    db = SessionLocal()
    db.execute(delete(Indicator))
    db.commit()
    db.close()


def test_import_is_idempotent(client, admin_headers):
    r1 = client.post("/api/v1/intel/import", headers=admin_headers, json=FIXTURE_BUNDLE)
    assert r1.status_code == 201
    r2 = client.post("/api/v1/intel/import", headers=admin_headers, json=FIXTURE_BUNDLE)
    assert r2.status_code == 201
    assert r2.json()["duplicates"] == 4, "second import of same bundle must fully dedupe"
    from app.core.database import SessionLocal
    from app.intelligence.models import Indicator
    from sqlalchemy import delete

    db = SessionLocal()
    db.execute(delete(Indicator))
    db.commit()
    db.close()


def test_import_rejects_non_stix(client, admin_headers):
    r = client.post("/api/v1/intel/import", headers=admin_headers, json={"type": "nope"})
    assert r.status_code == 422


def test_import_requires_admin(client, admin_headers):
    client.post("/api/v1/auth/users",
                json={"username": "intel-viewer", "password": "Viewer!Pass12", "role": "viewer"})
    tok = client.post("/api/v1/auth/login",
                      json={"username": "intel-viewer", "password": "Viewer!Pass12"}).json()["access_token"]
    r = client.post("/api/v1/intel/import",
                    headers={"Authorization": f"Bearer {tok}"}, json=FIXTURE_BUNDLE)
    assert r.status_code == 403


def test_event_enriched_with_active_indicator(client, admin_headers, intel_loaded):
    ingest(client, admin_headers,
           [{"type": "network", "payload": {"src_ip": "10.3.3.3", "dst_ip": "203.0.113.201",
                                            "dst_port": 443, "protocol": "tcp"}}])
    alerts = client.get("/api/v1/alerts?limit=100", headers=admin_headers).json()["alerts"]
    intel_alerts = [a for a in alerts if a["rule_id"] == "INTEL-IOC-001"]
    assert len(intel_alerts) == 1
    a = intel_alerts[0]
    assert a["entity_key"] == "203.0.113.201"
    assert a["evidence_event_ids"], "intel alerts must carry evidence"
    assert a["severity_id"] == 4  # confidence 80 -> high


def test_expired_indicator_never_matches(client, admin_headers, intel_loaded):
    ingest(client, admin_headers,
           [{"type": "network", "payload": {"src_ip": "10.3.3.4", "dst_ip": "192.0.2.199",
                                            "dst_port": 443, "protocol": "tcp"}}])
    alerts = client.get("/api/v1/alerts?limit=100", headers=admin_headers).json()["alerts"]
    assert not [a for a in alerts if a["entity_key"] == "192.0.2.199"]


def test_low_confidence_indicator_matches_but_never_alerts(client, admin_headers, intel_loaded):
    ingest(client, admin_headers,
           [{"type": "dns", "payload": {"host": "ws-low", "src_ip": "10.3.3.5",
                                        "dns_query": "sneaky.example"}}])
    # no alert below threshold
    alerts = client.get("/api/v1/alerts?limit=100", headers=admin_headers).json()["alerts"]
    assert not [a for a in alerts if a["entity_key"] == "sneaky.example"]
    # but the indicator's observation counter moved (evidence of the match)
    hit = client.get("/api/v1/intel/lookup?ioc_type=domain&value=sneaky.example",
                     headers=admin_headers)
    assert hit.status_code == 200
    indicators = hit.json()["matches"]
    assert indicators and indicators[0]["times_observed"] >= 1


def test_subdomain_matches_parent_indicator(client, admin_headers, intel_loaded):
    ingest(client, admin_headers,
           [{"type": "dns", "payload": {"host": "ws-sub", "src_ip": "10.3.3.6",
                                        "dns_query": "deep.evil.example"}}])
    alerts = client.get("/api/v1/alerts?limit=100", headers=admin_headers).json()["alerts"]
    assert [a for a in alerts if a["entity_key"] == "evil.example"]


def test_indicator_status_lifecycle(client, admin_headers, intel_loaded):
    r = client.get("/api/v1/intel/indicators?limit=50", headers=admin_headers)
    assert r.status_code == 200
    indicators = r.json()["indicators"]
    by_value = {i["value"]: i for i in indicators}
    assert by_value["203.0.113.201"]["status"] == "active"
    assert by_value["192.0.2.199"]["status"] == "expired"
    # provenance fields are always present
    assert by_value["203.0.113.201"]["source"] == "test-feed"
    assert by_value["203.0.113.201"]["confidence"] == 80


def test_intel_status_endpoint(client, admin_headers, intel_loaded):
    r = client.get("/api/v1/intel/status", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 4
    assert body["by_status"]["active"] == 3
    assert body["by_status"]["expired"] == 1