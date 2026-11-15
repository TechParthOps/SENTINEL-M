"""Authentication & user management API."""
from __future__ import annotations

import datetime as dt
import time
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core import audit
from app.core.config import settings
from app.core.database import get_db
from app.core.ratelimit import check_rate_limit
from app.core.security import (
    AdminUser,
    CurrentUser,
    authenticate,
    client_identity,
    decode_jwt,
    encode_jwt,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.core import mfa as mfa_core
from app.models.user import User
from app.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MfaActivateRequest,
    MfaDisableRequest,
    MfaRecoveryRequest,
    MfaVerifyRequest,
    TokenOut,
    UserCreate,
    UserOut,
)

router = APIRouter(prefix="/auth", tags=["auth"])

MFA_STEP_TOKEN_SECONDS = 300  # 5 minutes to complete the second factor


def _full_token(user: User) -> TokenOut:
    token = encode_jwt({"sub": str(user.id), "username": user.username, "role": user.role})
    return TokenOut(
        access_token=token,
        username=user.username,
        role=user.role,
        expires_in=settings.token_ttl_minutes * 60,
    )


def _mfa_token(user: User) -> TokenOut:
    token = encode_jwt({
        "sub": str(user.id), "username": user.username, "role": user.role,
        "scope": "mfa", "exp": int(time.time()) + MFA_STEP_TOKEN_SECONDS,
    })
    return TokenOut(
        access_token=token,
        username=user.username,
        role=user.role,
        expires_in=MFA_STEP_TOKEN_SECONDS,
        mfa_required=True,
    )


@router.post("/login", response_model=TokenOut)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    check_rate_limit(request, "auth.login", settings.login_ratelimit_per_min)
    user = authenticate(req.username, req.password, db)
    if user is None:
        audit.record("auth.login", actor=req.username, details={"result": "failure"})
        raise HTTPException(401, "invalid credentials")
    audit.record(
        "auth.login", actor=user.username,
        details={"result": "success", "role": user.role,
                 "mfa": "required" if user.mfa_enabled else "not_enabled"},
    )
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    if user.mfa_enabled:
        # first factor only — the real session token is issued after step-up
        return _mfa_token(user)
    return _full_token(user)


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser):
    return user


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    user: CurrentUser,
    db: Session = Depends(get_db),
):
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(400, "current password is incorrect")
    user.password_hash = hash_password(validate_password_policy(req.new_password))
    user.must_change_password = False
    db.commit()
    audit.record("auth.password_change", actor=user.username, details={"result": "success"})
    return {"status": "changed"}


@router.get("/bootstrap-status")
def bootstrap_status(db: Session = Depends(get_db)):
    """Public: has the first account been created yet? Drives the first-launch
    account-choice screen in the UI. Never leaks whether specific users exist
    beyond the count needed for that decision."""
    count = db.query(User).count()
    return {
        "needs_setup": count == 0,
        "user_count": count,
        "allow_self_registration": settings.allow_self_registration,
    }


@router.get("/users", response_model=list[UserOut])
def list_users(admin: AdminUser, db: Session = Depends(get_db)):
    audit.record("auth.users_list", actor=admin.username, details={})
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(req: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Privileged creation requires an admin token. `viewer`/`analyst` self-registration
    is policy-controlled (settings.allow_self_registration) and audit-recorded.

    First-launch exception: when the database has NO users yet, the caller may create
    the very first account with any role (administrator or normal user) — that is the
    bootstrap flow driven by GET /auth/bootstrap-status. After the first account
    exists this exception never applies again.

    Rationale (see SECURITY.md): Phase 1 is a local-first tool where bootstrapping a
    small team without an invite flow is the pragmatic default; set
    SENTINEL_ALLOW_SELF_REGISTRATION=false to require admin for all creation.
    """
    has_admin = _caller_is_admin(request)
    bootstrapping = db.query(User).count() == 0
    if not has_admin and not bootstrapping:
        if not settings.allow_self_registration:
            raise HTTPException(401, "authentication required")
        if req.role not in ("viewer", "analyst"):
            raise HTTPException(403, "self-registration may not create admin accounts")
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(409, "username already exists")
    user = User(
        username=req.username,
        password_hash=hash_password(req.password),
        display_name=req.display_name or req.username,
        role=req.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    audit.record(
        "auth.user_create",
        actor="admin" if has_admin else "anon",
        details={"username": user.username, "role": user.role,
                 "privileged": has_admin, "bootstrap": bootstrapping},
    )
    return user


def _caller_is_admin(request: Request) -> bool:
    """Best-effort check of the Authorization header (secrets module stays pure)."""
    from app.core.security import decode_jwt  # noqa: F811 (re-exported for this helper)

    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return False
    try:
        claims = decode_jwt(header[7:])
    except Exception:
        return False
    return claims.get("role") == "admin"


# ----------------------------------------------------------------- MFA (Phase 7)
# TOTP (RFC 6238) second factor + single-use recovery codes. The secret and hashed
# recovery codes live in the users row; plaintext recovery codes are shown once.


@router.get("/mfa/status")
def mfa_status(user: CurrentUser):
    return {
        "enabled": bool(user.mfa_enabled),
        "pending_enrollment": bool(user.mfa_secret) and not user.mfa_enabled,
        "enrolled_at": user.mfa_enrolled_at.isoformat() if user.mfa_enrolled_at else None,
        "recovery_codes_remaining": mfa_core.remaining_recovery_codes(user.mfa_recovery or "[]"),
    }


@router.post("/mfa/setup", status_code=201)
def mfa_setup(user: CurrentUser, db: Session = Depends(get_db)):
    """Start enrollment: generates a TOTP secret + recovery codes.

    MFA stays disabled until /mfa/activate succeeds, so a half-finished enrollment
    can never lock the operator out.
    """
    if user.mfa_enabled:
        raise HTTPException(409, "mfa already enabled")
    secret = mfa_core.generate_secret()
    codes = mfa_core.generate_recovery_codes()
    user.mfa_secret = secret
    user.mfa_recovery = mfa_core.hash_recovery_codes(codes)
    db.commit()
    audit.record("auth.mfa_enrollment_started", actor=user.username, details={})
    return {
        "status": "pending",
        "secret": secret,
        "provisioning_uri": mfa_core.provisioning_uri(secret, user.username),
        "recovery_codes": codes,  # shown exactly once, here
        "digits": mfa_core.TOTP_DIGITS,
        "period": mfa_core.TOTP_STEP_SECONDS,
    }


@router.post("/mfa/activate")
def mfa_activate(req: MfaActivateRequest, user: CurrentUser, db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(409, "mfa already enabled")
    if not user.mfa_secret:
        raise HTTPException(409, "no pending enrollment — call /auth/mfa/setup first")
    if not mfa_core.verify_totp(user.mfa_secret, req.code):
        audit.record("auth.mfa_activate", actor=user.username, details={"result": "failure"})
        raise HTTPException(400, "invalid authenticator code")
    user.mfa_enabled = True
    user.mfa_enrolled_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    audit.record("auth.mfa_activate", actor=user.username, details={"result": "success"})
    return {"status": "enabled", "enrolled_at": user.mfa_enrolled_at.isoformat()}


@router.post("/mfa/verify", response_model=TokenOut)
def mfa_verify(req: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)):
    """Exchange a step-up token + TOTP code for a full session token."""
    check_rate_limit(request, "auth.mfa_verify", 10)
    try:
        claims = decode_jwt(req.mfa_token)
    except Exception:
        raise HTTPException(401, "invalid or expired mfa token") from None
    if claims.get("scope") != "mfa":
        raise HTTPException(401, "token is not an mfa step-up token")
    user = db.get(User, claims.get("sub"))
    if user is None or not user.is_active or not user.mfa_enabled:
        raise HTTPException(401, "invalid or expired mfa token")
    if not mfa_core.verify_totp(user.mfa_secret, req.code):
        audit.record("auth.mfa_verify", actor=user.username, details={"result": "failure"})
        raise HTTPException(401, "invalid authenticator code")
    audit.record("auth.mfa_verify", actor=user.username, details={"result": "success"})
    return _full_token(user)


@router.post("/mfa/recovery-login", response_model=TokenOut)
def mfa_recovery_login(req: MfaRecoveryRequest, request: Request, db: Session = Depends(get_db)):
    """Consume a single-use recovery code to obtain a full session token."""
    check_rate_limit(request, "auth.mfa_recovery", 5)
    try:
        claims = decode_jwt(req.mfa_token)
    except Exception:
        raise HTTPException(401, "invalid or expired mfa token") from None
    if claims.get("scope") != "mfa":
        raise HTTPException(401, "token is not an mfa step-up token")
    user = db.get(User, claims.get("sub"))
    if user is None or not user.is_active or not user.mfa_enabled:
        raise HTTPException(401, "invalid or expired mfa token")
    ok, remaining = mfa_core.consume_recovery_code(user.mfa_recovery or "[]", req.recovery_code)
    if not ok:
        audit.record("auth.mfa_recovery", actor=user.username, details={"result": "failure"})
        raise HTTPException(401, "invalid recovery code")
    user.mfa_recovery = remaining
    db.commit()
    audit.record(
        "auth.mfa_recovery", actor=user.username,
        details={"result": "success",
                 "remaining": mfa_core.remaining_recovery_codes(remaining)},
    )
    return _full_token(user)


@router.post("/mfa/disable")
def mfa_disable(req: MfaDisableRequest, user: CurrentUser, db: Session = Depends(get_db)):
    """Disable MFA. Requires BOTH the current password and a valid live code."""
    if not user.mfa_enabled:
        raise HTTPException(409, "mfa not enabled")
    if not verify_password(req.password, user.password_hash):
        audit.record("auth.mfa_disable", actor=user.username, details={"result": "bad_password"})
        raise HTTPException(400, "password is incorrect")
    if not mfa_core.verify_totp(user.mfa_secret, req.code):
        audit.record("auth.mfa_disable", actor=user.username, details={"result": "bad_code"})
        raise HTTPException(400, "invalid authenticator code")
    user.mfa_secret = None
    user.mfa_enabled = False
    user.mfa_recovery = None
    user.mfa_enrolled_at = None
    db.commit()
    audit.record("auth.mfa_disable", actor=user.username, details={"result": "success"})
    return {"status": "disabled"}