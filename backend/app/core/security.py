"""Authentication & authorization core (ADR-002, ADR-003).

- Password hashing: PBKDF2-HMAC-SHA256 (stdlib), parameters embedded for upgrades.
- JWT: HS256 implemented on stdlib hmac/base64url; constant-time verification.
- RBAC: roles viewer < analyst < admin, enforced per-route via dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db

PBKDF2_ITERATIONS = 600_000
PBKDF2_PREFIX = "pbkdf2_sha256"

ROLES = ("viewer", "analyst", "admin")
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}

# ---------------------------------------------------------------- passwords


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_PREFIX}${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$")
        if algo != PBKDF2_PREFIX:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


_DUMMY_HASH = hash_password("dummy-password-for-timing")


def validate_password_policy(password: str) -> str:
    """Policy: >=10 chars, >=1 letter, >=1 digit. Raises ValueError with reason."""
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    if not any(c.isalpha() for c in password):
        raise ValueError("password must contain at least one letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("password must contain at least one digit")
    return password


# ---------------------------------------------------------------------- JWT


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def encode_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body.setdefault("iat", int(time.time()))
    body.setdefault("exp", int(time.time()) + settings.token_ttl_minutes * 60)
    segments = [
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
        _b64url_encode(json.dumps(body, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode()
    sig = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
    segments.append(_b64url_encode(sig))
    return ".".join(segments)


class TokenError(Exception):
    pass


def decode_jwt(token: str) -> dict:
    try:
        header_b64, body_b64, sig_b64 = token.split(".")
    except ValueError:
        raise TokenError("malformed token")
    signing_input = f"{header_b64}.{body_b64}".encode()
    expected = hmac.new(settings.secret_key.encode(), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_encode(expected), sig_b64):
        raise TokenError("bad signature")
    try:
        body = json.loads(_b64url_decode(body_b64))
    except Exception:
        raise TokenError("bad payload")
    exp = body.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        raise TokenError("expired")
    return body


# ------------------------------------------------------------- dependencies

bearer = HTTPBearer(auto_error=False)


def authenticate(username: str, password: str, db: Session):
    """Blind login: unknown users still run a hash to equalize timing."""
    from app.models.user import User  # local import avoids circularity at import time

    user = db.query(User).filter(User.username == username).first()
    stored = user.password_hash if user else _DUMMY_HASH
    ok = verify_password(password, stored)
    if not user or not ok:
        return None
    return user


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    db: Session = Depends(get_db),
):
    from fastapi import HTTPException

    if creds is None or not creds.credentials:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_jwt(creds.credentials)
    except TokenError as exc:
        raise HTTPException(
            401, f"invalid token: {exc}", headers={"WWW-Authenticate": "Bearer"}
        ) from None
    # Phase 7: an MFA step-up token may only be exchanged at /auth/mfa/*; it must
    # never authorize a normal API call (defence against token-scope confusion).
    if claims.get("scope") == "mfa":
        raise HTTPException(
            401, "mfa step-up required", headers={"WWW-Authenticate": "Bearer"}
        )
    from app.models.user import User

    user = db.get(User, claims.get("sub"))
    if user is None or not user.is_active:
        raise HTTPException(401, "user no longer valid")
    return user


CurrentUser = Annotated[object, Depends(get_current_user)]


def require_roles(*roles: str):
    """Dependency factory: caller must have one of `roles` (role rank >= min role)."""

    def dependency(request: Request, user: CurrentUser, db: Session = Depends(get_db)) -> object:
        from fastapi import HTTPException

        if getattr(user, "role", None) not in roles:
            raise HTTPException(403, f"role '{getattr(user, 'role', None)}' may not perform this action")
        return user

    return dependency


AdminUser = Annotated[object, Depends(require_roles("admin"))]
AnalystUser = Annotated[object, Depends(require_roles("admin", "analyst"))]


def client_identity(request: Request) -> str:
    """Best-effort client key for rate limiting (token sub if present, else IP)."""
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else "") or (request.client.host if request.client else "unknown")