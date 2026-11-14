"""Autonomous investigation agents tests (Phase 4)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tests.conftest import ingest


def _make_bruteforce_alert(client, admin_headers, host="ws-42"):
    events = [
        {"type": "auth", "payload": {"src_ip": "203.0.113.99", "user": "svc-backup",
                                     "outcome": "failure", "host": host,
                                     "message": "failed password"},
         "time": (datetime.now(timezone.utc) - timedelta(minutes=11 - i)).isoformat()}
        for i in range(12)
    ]
    r = ingest(client, admin_headers, events, source="agents-test-sensor")
    assert r.status_code == 200, r.text
    r = client.get("/api/v1/alerts?limit=50", headers=admin_headers)
    assert r.status_code == 200
    alerts = [a for a in r.json()["alerts"] if a["rule_id"] == "AUTH-BRUTEFORCE-001"]
    assert alerts, "brute-force alert expected"
    return alerts[0]


def _feed_indicator():
    import json

    from app.intelligence.engine import feeds_dir

    feed = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--b3c1f1e4-1111-5a2b-9c1d-agents111111",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "name": "agents-test C2",
                "indicator_types": ["malicious-activity"],
                "pattern": "[ipv4-addr:value = '203.0.113.99']",
                "pattern_type": "stix",
                "valid_from": "2026-01-01T00:00:00Z",
                "confidence": 90,
                "labels": ["agents-test"],
            }
        ],
    }
    path = feeds_dir() / "agents-test-feed.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(feed))
    return path


def test_investigation_on_alert_completes_with_chain(client, admin_headers):
    alert = _make_bruteforce_alert(client, admin_headers)
    r = client.post("/api/v1/agents/investigations", headers=admin_headers,
                    json={"subject_type": "alert", "subject_id": alert["id"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed"
    assert body["subject_id"] == alert["id"]
    agents_ran = {t["agent"] for t in body["tasks"]}
    assert {"alert_triage", "asset_context", "intel_check", "related_activity", "synthesis"} <= agents_ran
    assert all(t["status"] in ("completed", "skipped") for t in body["tasks"])
    assert body["verdict"] in ("benign", "suspicious", "malicious", "unknown")
    assert body["summary"]

    # evidence chain exists and verifies
    ev = client.get(f"/api/v1/agents/investigations/{body['id']}/evidence", headers=admin_headers)
    assert ev.status_code == 200
    ev = ev.json()
    assert ev["count"] >= 1
    assert ev["chain_valid"] is True
    kinds = {e["kind"] for e in ev["evidence"]}
    assert "alert" in kinds
    # hash chain links
    rows = ev["evidence"]
    for prev, cur in zip(rows, rows[1:]):
        assert cur["prev_hash"] == prev["sha256"]


def test_investigation_malicious_verdict_on_intel_hit(client, admin_headers):
    path = _feed_indicator()
    reload_r = client.post("/api/v1/intel/feeds/reload", headers=admin_headers)
    assert reload_r.status_code == 200
    path.unlink()

    alert = _make_bruteforce_alert(client, admin_headers, host="ws-99")
    r = client.post("/api/v1/agents/investigations", headers=admin_headers,
                    json={"subject_type": "alert", "subject_id": alert["id"]})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "malicious"
    synthesis = next(t for t in body["tasks"] if t["agent"] == "synthesis")
    assert synthesis["output"]["intel_hits"] >= 1
    # the intel evidence row exists
    ev = client.get(f"/api/v1/agents/investigations/{body['id']}/evidence", headers=admin_headers)
    kinds = {e["kind"] for e in ev.json()["evidence"]}
    assert "intel" in kinds


def test_entity_investigation_and_unknown_subject(client, admin_headers):
    r = client.post("/api/v1/agents/investigations", headers=admin_headers,
                    json={"subject_type": "entity", "subject_id": "10.10.10.77"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "completed"
    assert body["subject_type"] == "entity"

    r = client.post("/api/v1/agents/investigations", headers=admin_headers,
                    json={"subject_type": "alert", "subject_id": "does-not-exist"})
    assert r.status_code == 404


def test_viewer_cannot_start_investigations(client, admin_headers):
    reg = client.post("/api/v1/auth/users", headers=admin_headers,
                      json={"username": "agents-viewer", "password": "Viewer!Pass12",
                            "role": "viewer"})
    assert reg.status_code == 201, reg.text
    token = client.post("/api/v1/auth/login",
                        json={"username": "agents-viewer", "password": "Viewer!Pass12"}
                        ).json()["access_token"]
    r = client.post("/api/v1/agents/investigations", headers={"Authorization": f"Bearer {token}"},
                    json={"subject_type": "entity", "subject_id": "10.10.10.5"})
    assert r.status_code == 403


def test_investigations_listed(client, admin_headers):
    r = client.get("/api/v1/agents/investigations", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["total"] >= 1
