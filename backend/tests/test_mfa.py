"""MFA (TOTP + recovery codes) tests â€” Phase 7.

Every assertion runs against the real TOTP code the server would expect, so the
RFC-6238 path, the step-up token scope boundary and code consumption are all
exercised end-to-end over HTTP.
"""
from __future__ import annotations

import time

import pytest

from app.core.mfa import generate_totp


@pytest.fixture(autouse=True)
def _reset_admin_mfa():
    """Users persist for the whole test session â€” clear any MFA state so each test
    starts from a known baseline (enrollment is otherwise one-way per admin user)."""
    from app.core.database import SessionLocal
    from app.models.user import User
    from sqlalchemy import update

    db = SessionLocal()
    try:
        db.execute(
            update(User)
            .where(User.mfa_secret.isnot(None) | User.mfa_enabled.is_(True))
            .values(mfa_secret=None, mfa_enabled=False, mfa_recovery=None, mfa_enrolled_at=None)
        )
        db.commit()
    finally:
        db.close()
    yield


def _current_code(secret: str) -> str:
    # server-side drift window is Â±1 step; a fresh code is always valid
    return generate_totp(secret, at=time.time())


def _login(client, password):
    return client.post("/api/v1/auth/login", json={"username": "admin", "password": password})


ADMIN_PASSWORD = "TestAdmin!Pass123"  # keep in sync with tests/conftest.py


def _enroll(client, headers):
    r = client.post("/api/v1/auth/mfa/setup", headers=headers)
    assert r.status_code == 201, r.text
    body = r.json()
    secret, codes = body["secret"], body["recovery_codes"]
    act = client.post("/api/v1/auth/mfa/activate", headers=headers,
                      json={"code": _current_code(secret)})
    assert act.status_code == 200, act.text
    return secret, codes


def test_setup_returns_secret_and_recovery_codes(client, admin_headers):
    r = client.post("/api/v1/auth/mfa/setup", headers=admin_headers)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending"
    assert len(body["secret"]) >= 16
    assert "otpauth://totp/" in body["provisioning_uri"]
    assert len(body["recovery_codes"]) == 5
    st = client.get("/api/v1/auth/mfa/status", headers=admin_headers)
    assert st.json()["pending_enrollment"] is True
    assert st.json()["enabled"] is False


def test_activate_rejects_wrong_code(client, admin_headers):
    setup = client.post("/api/v1/auth/mfa/setup", headers=admin_headers).json()
    bad = client.post("/api/v1/auth/mfa/activate", headers=admin_headers, json={"code": "000000"})
    assert bad.status_code == 400, bad.text
    st = client.get("/api/v1/auth/mfa/status", headers=admin_headers)
    assert st.json()["enabled"] is False  # half-finished enrollment never locks out


def test_full_mfa_flow_login_step_up_and_recovery(client, admin_headers):
    secret, codes = _enroll(client, admin_headers)

    # password alone yields a step-up token, not a session
    r = _login(client, ADMIN_PASSWORD)
    assert r.status_code == 200, r.text
    step = r.json()
    assert step["mfa_required"] is True
    me_bad = client.get("/api/v1/auth/me",
                       headers={"Authorization": f"Bearer {step['access_token']}"})
    assert me_bad.status_code == 401  # MFA tokens never authorize normal API calls

    # correct TOTP completes the login
    ok = client.post("/api/v1/auth/mfa/verify",
                     json={"mfa_token": step["access_token"], "code": _current_code(secret)})
    assert ok.status_code == 200, ok.text
    full = ok.json()
    assert full["mfa_required"] is False
    me = client.get("/api/v1/auth/me",
                    headers={"Authorization": f"Bearer {full['access_token']}"})
    assert me.status_code == 200, me.text

    # recovery code also completes login â€” and is single-use
    r2 = _login(client, ADMIN_PASSWORD)
    rec = client.post("/api/v1/auth/mfa/recovery-login",
                      json={"mfa_token": r2.json()["access_token"],
                            "recovery_code": codes[0]})
    assert rec.status_code == 200, rec.text
    r3 = _login(client, ADMIN_PASSWORD)
    rec2 = client.post("/api/v1/auth/mfa/recovery-login",
                       json={"mfa_token": r3.json()["access_token"],
                             "recovery_code": codes[0]})
    assert rec2.status_code == 401  # consumed
    st = client.get("/api/v1/auth/mfa/status", headers=admin_headers)
    assert st.json()["recovery_codes_remaining"] == 4


def test_wrong_code_rejected(client, admin_headers):
    secret, _ = _enroll(client, admin_headers)
    step = _login(client, ADMIN_PASSWORD).json()
    bad = client.post("/api/v1/auth/mfa/verify",
                      json={"mfa_token": step["access_token"], "code": "123456"})
    # the only risk is a genuine (but astronomically unlikely) code collision
    assert bad.status_code in (400, 401)


def test_disable_requires_password_and_code(client, admin_headers):
    secret, _ = _enroll(client, admin_headers)
    # wrong password
    bad_pw = client.post("/api/v1/auth/mfa/disable", headers=admin_headers,
                         json={"password": "wrong-password-1", "code": _current_code(secret)})
    assert bad_pw.status_code == 400
    # correct both
    ok = client.post("/api/v1/auth/mfa/disable", headers=admin_headers,
                     json={"password": ADMIN_PASSWORD, "code": _current_code(secret)})
    assert ok.status_code == 200, ok.text
    st = client.get("/api/v1/auth/mfa/status", headers=admin_headers)
    assert st.json()["enabled"] is False
    # login no longer requires the second factor
    r = _login(client, ADMIN_PASSWORD)
    assert r.json()["mfa_required"] is False
