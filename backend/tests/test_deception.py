"""Deception / honeypot tests (Phase 5): isolation, interaction capture, safe stop."""
from __future__ import annotations

import socket
import time


def _create_pot(client, admin_headers, name, kind, port=0):
    r = client.post("/api/v1/deception/pots", headers=admin_headers,
                    json={"name": name, "kind": kind, "port": port})
    assert r.status_code == 201, r.text
    return r.json()


def test_create_and_start_tcp_banner_and_capture_interaction(client, admin_headers):
    pot = _create_pot(client, admin_headers, "hp-ssh-decoy", "tcp_banner", port=0)
    assert pot["status"] == "stopped"
    assert pot["decoy_identity"]  # random decoy identity exists
    # port 0 not allowed for listeners
    r = client.post(f"/api/v1/deception/pots/{pot['id']}/start", headers=admin_headers)
    assert r.status_code == 422

    # recreate on a real unprivileged port
    pot = _create_pot(client, admin_headers, "hp-ssh-decoy-2", "tcp_banner", port=15222)
    r = client.post(f"/api/v1/deception/pots/{pot['id']}/start", headers=admin_headers)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "running"

    # connect like an attacker would
    s = socket.create_connection(("127.0.0.1", 15222), timeout=5)
    banner = s.recv(64)
    s.sendall(b"probe-from-test")
    s.close()
    time.sleep(0.5)  # allow the handler thread to record

    ints = client.get(f"/api/v1/deception/pots/{pot['id']}/interactions", headers=admin_headers)
    assert ints.status_code == 200
    body = ints.json()
    assert body["total"] >= 1
    assert body["interactions"][0]["kind"] == "tcp_connect"
    assert body["interactions"][0]["source_ip"] == "127.0.0.1"

    # an interaction raises a real alert
    alerts = client.get("/api/v1/alerts?limit=100", headers=admin_headers).json()["alerts"]
    assert any(a["rule_id"] == "DECEPTION-HP-001" for a in alerts)

    # safe stop: listener closed
    r = client.post(f"/api/v1/deception/pots/{pot['id']}/stop", headers=admin_headers)
    assert r.status_code == 200 and r.json()["status"] == "stopped"
    try:
        socket.create_connection(("127.0.0.1", 15222), timeout=2).close()
        raise AssertionError("listener still accepting connections after stop")
    except OSError:
        pass


def test_canary_token_hit(client, admin_headers):
    pot = _create_pot(client, admin_headers, "hp-canary-doc", "canary_token")
    assert pot["canary_path"].startswith("/deception/canary/")
    # unauthenticated hit (by design); canary_path is API-relative
    r = client.get("/api/v1" + pot["canary_path"])
    assert r.status_code == 200 and r.json()["recorded"] is True
    ints = client.get(f"/api/v1/deception/pots/{pot['id']}/interactions", headers=admin_headers)
    assert ints.json()["total"] == 1
    assert ints.json()["interactions"][0]["kind"] == "canary_hit"


def test_pots_admin_only(client, admin_headers):
    client.post("/api/v1/auth/users", headers=admin_headers,
                json={"username": "decep-viewer", "password": "Viewer!Pass12", "role": "viewer"})
    token = client.post("/api/v1/auth/login",
                        json={"username": "decep-viewer", "password": "Viewer!Pass12"}
                        ).json()["access_token"]
    r = client.post("/api/v1/deception/pots", headers={"Authorization": f"Bearer {token}"},
                    json={"name": "hp-x", "kind": "tcp_banner", "port": 15333})
    assert r.status_code == 403
    # viewer can still list and view interactions (read-only)
    assert client.get("/api/v1/deception/pots", headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_invalid_kind_rejected(client, admin_headers):
    r = client.post("/api/v1/deception/pots", headers=admin_headers,
                    json={"name": "hp-bad", "kind": "root_shell", "port": 0})
    assert r.status_code == 422
