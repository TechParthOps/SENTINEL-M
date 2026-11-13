"""In-memory fixed-window rate limiter (single-node, Phase 1)."""
from __future__ import annotations

import threading
import time

from collections import defaultdict

from fastapi import HTTPException, Request

_lock = threading.Lock()
_hits: dict[tuple[str, str], tuple[int, float]] = defaultdict(lambda: (0, 0.0))  # key -> (count, window_start)

from app.core.config import settings  # noqa: E402


def check_rate_limit(request: Request, bucket: str, per_minute: int) -> None:
    if not settings.ratelimit_enabled:
        return
    key = (bucket, _identity(request))
    now = time.time()
    with _lock:
        count, window_start = _hits[key]
        if now - window_start >= 60.0:
            window_start, count = now, 0
        count += 1
        _hits[key] = (count, window_start)
    if count > per_minute:
        retry_after = max(1, int(60 - (now - window_start)))
        raise HTTPException(429, f"rate limit exceeded; retry in {retry_after}s")


def _identity(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd else "") or (
        request.client.host if request.client else "unknown"
    )