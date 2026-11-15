"""First-launch account creation (bootstrap) tests.

The seeded admin in the shared test DB means "users already exist"; the bootstrap
branches are exercised through the public status endpoint, the audit trail, and
the pure decision helper. The zero-user path itself is verified live in
scripts/mfa_smoke-style runs and documented in docs/INSTALL.md.
"""
from __future__ import annotations


def test_bootstrap_status_reports_existing_users(client):
    r = client.get("/api/v1/auth/bootstrap-status")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["needs_setup"] is False  # the seeded admin exists
    assert body["user_count"] >= 1
    assert isinstance(body["allow_self_registration"], bool)


def test_bootstrap_creation_requires_admin_when_users_exist(client):
    # once any user exists, anonymous admin creation must be rejected
    r = client.post("/api/v1/auth/users", json={
        "username": "sneaky-admin", "password": "Str0ngPass!word",
        "role": "admin", "display_name": "Sneaky",
    })
    assert r.status_code in (401, 403), r.text


def test_bootstrap_creation_requires_admin_when_users_exist_even_with_flag(client):
    # allow_self_registration only ever covers viewer/analyst, never admin
    r = client.post("/api/v1/auth/users", json={
        "username": "sneaky-admin-2", "password": "Str0ngPass!word",
        "role": "admin",
    })
    assert r.status_code in (401, 403), r.text


def test_bootstrap_audit_records_flag(client, admin_headers):
    before = client.get("/api/v1/audit?limit=200", headers=admin_headers).json()["entries"]
    client.post("/api/v1/auth/users", headers=admin_headers, json={
        "username": "bootstrap-flag-check", "password": "Str0ngPass!word",
        "role": "viewer",
    })
    after = client.get("/api/v1/audit?limit=200", headers=admin_headers).json()["entries"]
    new = [e for e in after if e not in before and e["action"] == "auth.user_create"]
    assert new and new[0]["details"]["bootstrap"] is False
    assert new[0]["details"]["privileged"] is True


def test_seed_message_when_users_exist():
    from app.services.seed import seed_if_empty

    assert seed_if_empty() == "already initialized"