"""Module health registry — every architectural module reports here."""
from __future__ import annotations

import threading
import time


class HealthRegistry:
    def __init__(self) -> None:
        self._checks: dict[str, callable] = {}
        self._lock = threading.Lock()

    def register(self, name: str, check) -> None:
        """check: zero-arg callable returning dict with at least {'status': 'ok'|'degraded'|'error'}."""
        with self._lock:
            self._checks[name] = check

    def names(self) -> list[str]:
        return sorted(self._checks)

    _RANK = {"ok": 0, "degraded": 1, "error": 2}

    def check(self) -> dict:
        modules: dict[str, dict] = {}
        worst = "ok"
        with self._lock:
            checks = dict(self._checks)
        for name, fn in checks.items():
            try:
                result = fn() or {}
                status = result.get("status", "ok")
                if status not in self._RANK:
                    status = "error"
                modules[name] = result
            except Exception as exc:  # a failing module must not crash health
                modules[name] = {"status": "error", "detail": str(exc)[:300]}
                status = "error"
            if self._RANK[status] > self._RANK[worst]:
                worst = status
        return {"status": worst, "modules": modules, "checked_at": time.time()}


registry = HealthRegistry()