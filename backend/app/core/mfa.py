"""Multi-factor authentication core (Phase 7) — TOTP per RFC 6238 + recovery codes.

Stdlib-only on purpose (hmac/hashlib/base64/secrets): no new runtime dependency, no
network, works fully offline. The TOTP secrets and recovery-code hashes live in the
users row; recovery codes are stored as SHA-256 hashes (the plaintext is shown exactly
once at enrollment).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_DRIFT_STEPS = 1  # accept one step of clock drift in either direction
RECOVERY_CODE_COUNT = 5


# ------------------------------------------------------------------- secrets


def generate_secret() -> str:
    """20 random bytes, base32 (no padding) — the standard authenticator-app secret."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_at(secret_b32: str, counter: int, digits: int = TOTP_DIGITS) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 4))
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(code_int).zfill(digits)[-digits:]


def generate_totp(secret_b32: str, at: float | None = None, digits: int = TOTP_DIGITS) -> str:
    """Current TOTP code (used by tests and by operators with an authenticator app)."""
    ts = int(time.time() if at is None else at)
    return _totp_at(secret_b32, ts // TOTP_STEP_SECONDS, digits)


def verify_totp(secret_b32: str, code: str, at: float | None = None) -> bool:
    """Constant-time verification allowing ±1 step of drift."""
    ts = int(time.time() if at is None else at)
    counter = ts // TOTP_STEP_SECONDS
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return False
    for drift in range(-TOTP_DRIFT_STEPS, TOTP_DRIFT_STEPS + 1):
        expected = _totp_at(secret_b32, counter + drift)
        if hmac.compare_digest(expected, code):
            return True
    return False


def provisioning_uri(secret_b32: str, username: str, issuer: str = "SENTINEL-M") -> str:
    """otpauth:// URI for authenticator apps (RFC 6238 §Appendix)."""
    label = f"{issuer}:{username}"
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={issuer}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"
    )


# ------------------------------------------------------------- recovery codes


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    return [secrets.token_hex(5) for _ in range(count)]


def hash_recovery_codes(codes: list[str]) -> str:
    """Store SHA-256 hashes as a JSON list (deterministic, one-way)."""
    return json.dumps([hashlib.sha256(c.encode()).hexdigest() for c in codes])


def consume_recovery_code(stored_json: str, code: str) -> tuple[bool, str]:
    """Single-use recovery codes. Returns (ok, updated_json)."""
    try:
        hashes = json.loads(stored_json or "[]")
    except Exception:
        hashes = []
    target = hashlib.sha256((code or "").strip().encode()).hexdigest()
    for i, h in enumerate(hashes):
        if hmac.compare_digest(h, target):
            remaining = [h for j, h in enumerate(hashes) if j != i]
            return True, json.dumps(remaining)
    return False, json.dumps(hashes)


def remaining_recovery_codes(stored_json: str) -> int:
    try:
        return len(json.loads(stored_json or "[]"))
    except Exception:
        return 0