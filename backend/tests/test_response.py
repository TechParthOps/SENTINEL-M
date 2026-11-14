"""Response engine tests (Phase 5): policy gating, approval, dry-run, rollback, verification."""
from __future__ import annotations

from app.core.config import settings
from tests.conftest import ingest


def _seed_asset(client, admin_headers, hostname="resp-host-1", criticality=2):
    r = client.post("/api/v1/assets", headers=admin_headers,
                    json={"hostname": hostname, "criticality": criticality, "asset_type": "server"})
    assert r.status_code in (200, 201), r.text
    return hostname


def _isolate_action(client, admin_headers, hostname, dry_run=False):
    r = client.post("/api/v1/response/actions", headers=admin_headers,
                    json={"action_type": "asset_isolate", "target_type": "asset",
                          "target": hostname, "reason": "contained compromise", "dry_run": dry_run})
    assert r.status_code == 201, r.text
    return r.json()


def test_disallowed_action_rejected(client, admin_headers):
    r = client.post("/api/v1/response/actions", headers=admin_headers,
                    json={"action_type": "rm_rf_everything", "target_type": "asset",
                          "target": "x", "reason": "test"})
    assert r.status_code == 422


def test_dry_run_simulates_without_effect(client, admin_headers):
    hostname = _seed_asset(client, admin_headers, "resp-dry-host")
    action = _isolate_action(client, admin_headers, hostname, dry_run=True)
    assert action["status"] == "dry_run"
    assert action["result"]["simulation"] is True
    assert action["result"]["would"] == "asset.isolated -> True"
    # state untouched
    assets = client.get("/api/v1/assets", headers=admin_headers).json()["assets"]
    target = next(a for a in assets if a["hostname"] == hostname)
    assert target.get("isolated") in (False, None)


def test_l2_noncritical_auto_executes_and_verifies(client, admin_headers):
    hostname = _seed_asset(client, admin_headers, "resp-auto-host", criticality=2)
    action = _isolate_action(client, admin_headers, hostname, dry_run=False)
    assert action["status"] == "verified", action
    assert action["verification"]["verified"] is True
    assets = client.get("/api/v1/assets", headers=admin_headers).json()["assets"]
    target = next(a for a in assets if a["hostname"] == hostname)
    assert target["isolated"] is True

    # rollback restores
    rb = client.post(f"/api/v1/response/actions/{action['id']}/rollback", headers=admin_headers)
    assert rb.status_code == 200, rb.text
    assert rb.json()["status"] == "rolled_back"
    assets = client.get("/api/v1/assets", headers=admin_headers).json()["assets"]
    assert next(a for a in assets if a["hostname"] == hostname)["isolated"] is False


def test_critical_asset_requires_approval(client, admin_headers):
    hostname = _seed_asset(client, admin_headers, "resp-crit-host", criticality=5)
    action = _isolate_action(client, admin_headers, hostname, dry_run=False)
    assert action["status"] == "requested"  # auto-execution withheld
    # execute without approval -> 403
    denied = client.post(f"/api/v1/response/actions/{action['id']}/execute", headers=admin_headers)
    assert denied.status_code == 403
    # approve then execute
    appr = client.post(f"/api/v1/response/actions/{action['id']}/approve", headers=admin_headers)
    assert appr.status_code == 200
    assert appr.json()["status"] == "approved"
    ex = client.post(f"/api/v1/response/actions/{action['id']}/execute", headers=admin_headers)
    assert ex.status_code == 200
    assert ex.json()["status"] == "verified"


def test_viewer_cannot_request_actions(client, admin_headers):
    client.post("/api/v1/auth/users", headers=admin_headers,
                json={"username": "resp-viewer", "password": "Viewer!Pass12", "role": "viewer"})
    token = client.post("/api/v1/auth/login",
                        json={"username": "resp-viewer", "password": "Viewer!Pass12"}
                        ).json()["access_token"]
    r = client.post("/api/v1/response/actions", headers={"Authorization": f"Bearer {token}"},
                    json={"action_type": "asset_isolate", "target_type": "asset",
                          "target": "x", "reason": "test"})
    assert r.status_code == 403


def test_emergency_stop_blocks_execution(client, admin_headers, monkeypatch):
    monkeypatch.setattr(settings, "response_enabled", False)
    hostname = _seed_asset(client, admin_headers, "resp-stop-host", criticality=2)
    action = _isolate_action(client, admin_headers, hostname, dry_run=False)
    # policy denies real execution while disabled; dry-runs still allowed
    dr = client.post("/api/v1/response/actions", headers=admin_headers,
                     json={"action_type": "asset_isolate", "target_type": "asset",
                           "target": hostname, "reason": "rehearsal", "dry_run": True})
    assert dr.status_code == 201 and dr.json()["status"] == "dry_run"
    assert action["status"] == "denied"
    monkeypatch.setattr(settings, "response_enabled", True)


def test_ip_denylist_roundtrip(client, admin_headers):
    r = client.post("/api/v1/response/actions", headers=admin_headers,
                    json={"action_type": "ip_denylist_add", "target_type": "ip",
                          "target": "198.51.100.66", "reason": "c2 endpoint"})
    assert r.status_code == 201
    action = r.json()
    assert action["status"] == "requested"  # L1: approval required
    # without approval, execution is rejected
    ex_denied = client.post(f"/api/v1/response/actions/{action['id']}/execute", headers=admin_headers)
    assert ex_denied.status_code == 403
    appr = client.post(f"/api/v1/response/actions/{action['id']}/approve", headers=admin_headers)
    assert appr.status_code == 200
    ex = client.post(f"/api/v1/response/actions/{action['id']}/execute", headers=admin_headers)
    assert ex.status_code == 200
    assert ex.json()["status"] == "verified"
    dl = client.get("/api/v1/response/denylist", headers=admin_headers).json()["entries"]
    assert any(e["ip"] == "198.51.100.66" for e in dl)
