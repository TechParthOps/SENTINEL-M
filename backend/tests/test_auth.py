"""Authentication, RBAC and user-management tests."""
from __future__ import annotations

from tests.conftest import ADMIN_PASSWORD


def test_login_success_and_me(client, admin_headers):
    r = client.get("/api/v1/auth/me", headers=admin_headers)
    assert r.status_code == 200
    me = r.json()
    assert me["username"] == "admin"
    assert me["role"] == "admin"


def test_login_wrong_password(client):
    r = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user_blind(client):
    r = client.post("/api/v1/auth/login", json={"username": "ghost-user", "password": "x"})
    assert r.status_code == 401


def test_invalid_token_rejected(client):
    r = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer not.a.jwt"})
    assert r.status_code == 401


def test_missing_token_rejected(client):
    r = client.get("/api/v1/auth/me")
    assert r.status_code == 401


def test_change_password_flow(client, admin_headers):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"username": "pwtest", "password": "Original!Pass1", "role": "analyst"})
    assert r.status_code == 201, r.text
    login1 = client.post("/api/v1/auth/login",
                         json={"username": "pwtest", "password": "Original!Pass1"})
    assert login1.status_code == 200
    token1 = login1.json()["access_token"]
    r = client.post("/api/v1/auth/change-password",
                    headers={"Authorization": f"Bearer {token1}"},
                    json={"current_password": "Original!Pass1", "new_password": "Changed!Pass99"})
    assert r.status_code == 200
    login2 = client.post("/api/v1/auth/login",
                         json={"username": "pwtest", "password": "Changed!Pass99"})
    assert login2.status_code == 200
    # old password no longer works
    assert client.post("/api/v1/auth/login",
                       json={"username": "pwtest", "password": "Original!Pass1"}).status_code == 401


def test_create_user_requires_admin(client):
    # login as analyst (created in earlier test) and attempt to create a user
    client.post("/api/v1/auth/users",
                json={"username": "rbac-analyst", "password": "Analyst!Pass1", "role": "analyst"})
    tok = client.post("/api/v1/auth/login",
                      json={"username": "rbac-analyst", "password": "Analyst!Pass1"}).json()["access_token"]
    r = client.post("/api/v1/auth/users", headers={"Authorization": f"Bearer {tok}"},
                    json={"username": "hacker", "password": "Whatever123!", "role": "admin"})
    assert r.status_code == 403


def test_duplicate_username_conflict(client, admin_headers):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"username": "pwtest", "password": "Whatever123!", "role": "viewer"})
    assert r.status_code == 409


def test_weak_password_rejected(client, admin_headers):
    r = client.post("/api/v1/auth/users", headers=admin_headers,
                    json={"username": "weakling", "password": "short", "role": "viewer"})
    assert r.status_code == 422


def test_admin_can_list_users(client, admin_headers):
    r = client.get("/api/v1/auth/users", headers=admin_headers)
    assert r.status_code == 200
    usernames = [u["username"] for u in r.json()]
    assert "admin" in usernames
