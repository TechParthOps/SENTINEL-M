"""Threat hunt API tests (Phase 4)."""
from __future__ import annotations

from tests.conftest import ingest


def test_hunt_by_ioc(client, admin_headers):
    ingest(client, admin_headers, [
        {"type": "network",
         "payload": {"src_ip": "10.9.9.5", "dst_ip": "198.51.100.23", "dst_port": 8443,
                     "message": "suspicious egress to hunt-target-host.example"}},
    ], source="hunt-sensor")
    r = client.get("/api/v1/hunt", headers=admin_headers,
                   params={"q": "198.51.100.23", "hours": 24})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_events"] >= 1
    assert any("198.51.100.23" in (e.get("dst_ip") or "") for e in body["events"])


def test_hunt_requires_analyst(client, admin_headers):
    reg = client.post("/api/v1/auth/users", headers=admin_headers,
                      json={"username": "hunt-viewer", "password": "Viewer!Pass12",
                            "role": "viewer"})
    assert reg.status_code == 201, reg.text
    token = client.post("/api/v1/auth/login",
                        json={"username": "hunt-viewer", "password": "Viewer!Pass12"}
                        ).json()["access_token"]
    r = client.get("/api/v1/hunt", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_hunt_class_and_window_filters(client, admin_headers):
    r = client.get("/api/v1/hunt", headers=admin_headers,
                   params={"class_name": "authentication", "hours": 1, "limit": 10})
    assert r.status_code == 200
    assert all("class_name" in e for e in r.json()["events"])
