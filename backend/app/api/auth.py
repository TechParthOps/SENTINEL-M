"""Authentication & user management API."""
from __future__ import annotations

import datetime as dt
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
    encode_jwt,
    hash_password,
    validate_password_policy,
    verify_password,
)
from app.models.user import User
from app.schemas import ChangePasswordRequest, LoginRequest, TokenOut, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    check_rate_limit(request, "auth.login", settings.login_ratelimit_per_min)
    user = authenticate(req.username, req.password, db)
    if user is None:
        audit.record("auth.login", actor=req.username, details={"result": "failure"})
        raise HTTPException(401, "invalid credentials")
    audit.record(
        "auth.login", actor=user.username, details={"result": "success", "role": user.role}
    )
    token = encode_jwt({"sub": str(user.id), "username": user.username, "role": user.role})
    user.last_login_at = dt.datetime.now(dt.timezone.utc)
    db.commit()
    return TokenOut(
        access_token=token,
        username=user.username,
        role=user.role,
        expires_in=settings.token_ttl_minutes * 60,
    )


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


@router.get("/users", response_model=list[UserOut])
def list_users(admin: AdminUser, db: Session = Depends(get_db)):
    audit.record("auth.users_list", actor=admin.username, details={})
    return db.query(User).order_by(User.id).all()


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(req: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Privileged creation requires an admin token. `viewer`/`analyst` self-registration
    is policy-controlled (settings.allow_self_registration) and audit-recorded.

    Rationale (see SECURITY.md): Phase 1 is a local-first tool where bootstrapping a
    small team without an invite flow is the pragmatic default; set
    SENTINEL_ALLOW_SELF_REGISTRATION=false to require admin for all creation.
    Self-registration can never create admin accounts.
    """
    has_admin = _caller_is_admin(request)
    if not has_admin:
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
        details={"username": user.username, "role": user.role, "privileged": has_admin},
    )
    return user


def _caller_is_admin(request: Request) -> bool:
    """Best-effort check of the Authorization header (secrets module stays pure)."""
    from app.core.security import decode_jwt

    header = request.headers.get("authorization", "")
    if not header.startswith("Bearer "):
        return False
    try:
        claims = decode_jwt(header[7:])
    except Exception:
        return False
    return claims.get("role") == "admin"