"""Identity engine + identity API tests (Phase 2)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tests.conftest import ingest


def _auth(client, admin_headers, user, country, minutes_ago, outcome="success"):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    return ingest(client, admin_headers, [{
        "type": "auth",
        "time": ts,
        "payload": {"user": user, "outcome": outcome, "geo_country": country,
                    "auth_protocol": "oidc"},
    }], source="idp-sensor")


def test_identity_summary_reports_auth_posture(client, admin_headers):
    _auth(client, admin_headers, "alice", "DE", 30)
    _auth(client, admin_headers, "alice", "US", 10)
    _auth(client, admin_headers, "bob", "FR", 5, outcome="failure")

    r = client.get("/api/v1/identity/summary", headers=admin_headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["auth_events_24h"] >= 3
    assert body["successes_24h"] >= 2
    assert body["failures_24h"] >= 1
    assert body["distinct_users"] >= 2
    # alice's DE→US jump within the 120-minute window is a geo-change signal
    assert body["geo_change_events_24h"] >= 1
    assert "geolocation" in body["limitation"].lower() or "geo_country" in body["limitation"]


def test_impossible_travel_rule_fires(client, admin_headers):
    _auth(client, admin_headers, "carol", "AU", 40)
    _auth(client, admin_headers, "carol", "BR", 20)  # ~2h flight apart within minutes

    r = client.get("/api/v1/alerts?limit=50", headers=admin_headers)
    assert r.status_code == 200
    rule_ids = [a["rule_id"] for a in r.json()["alerts"]]
    assert "ID-IMPOSSIBLE-TRAVEL-001" in rule_ids


def test_identity_summary_requires_auth(client):
    r = client.get("/api/v1/identity/summary")
    assert r.status_code in (401, 403)
