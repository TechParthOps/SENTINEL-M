"""STIX 2.1 JSON bundle import (documented subset).

Supported object types: `indicator` with patterns over ipv4-addr, domain-name,
url, email-addr and file hashes (SHA-256/SHA-1/MD5). This is the minimum useful
subset; richer STIX (relationship graphs, sightings) is a later-phase extension.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_PATTERN_RULES: list[tuple[str, str]] = [
    (r"ipv4-addr:value\s*=\s*'([^']+)'", "ipv4"),
    (r"domain-name:value\s*=\s*'([^']+)'", "domain"),
    (r"url:value\s*=\s*'([^']+)'", "url"),
    (r"email-addr:value\s*=\s*'([^']+)'", "email"),
    (r"file:hashes\.'?SHA-256'?\s*=\s*'([^']+)'", "sha256"),
    (r"file:hashes\.'?SHA256'?\s*=\s*'([^']+)'", "sha256"),
    (r"file:hashes\.'?SHA-1'?\s*=\s*'([^']+)'", "sha1"),
    (r"file:hashes\.'?MD5'?\s*=\s*'([^']+)'", "md5"),
]

def _dt(value) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None


def _safe_confidence(value, default: int = 50) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return default


def parse_bundle(bundle: dict, default_source: str = "stix-import") -> list[dict]:
    """Extract indicator dicts from a STIX 2.1 bundle. Raises ValueError on malformed input."""
    if not isinstance(bundle, dict) or bundle.get("type") not in ("bundle", "collection"):
        raise ValueError("not a STIX 2.1 bundle (missing type=bundle)")
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("bundle.objects must be a list")

    indicators: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        if not pattern:
            continue
        types_found = None  # reserved for future relationship-aware import
        values: list[tuple[str, str]] = []
        for regex, ioc_type in _PATTERN_RULES:
            for match in re.findall(regex, pattern, flags=re.IGNORECASE):
                value = match.strip().lower()
                if not _sane_value(ioc_type, value):
                    continue
                values.append((ioc_type, value))
        for ioc_type, value in values:
            key = (ioc_type, value)
            if key in seen:
                continue
            seen.add(key)
            indicators.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "source": obj.get("x_source", default_source),
                    "source_type": "feed",
                    "confidence": _safe_confidence(obj.get("confidence", 50)),
                    "reliability": str(obj.get("x_reliability", "C"))[:8],
                    "valid_from": _dt(obj.get("valid_from")),
                    "valid_until": _dt(obj.get("valid_until")),
                    "context": str(obj.get("description", ""))[:1024],
                    "tags": list(obj.get("labels", [])),
                    "labels": list(obj.get("labels", [])),
                    "stix_id": obj.get("id", ""),
                    "created": _dt(obj.get("created")),
                    "raw": {"stix_id": obj.get("id"), "pattern": pattern[:512]},
                }
            )
    return indicators


def _sane_value(ioc_type: str, value: str) -> bool:
    if ioc_type == "ipv4":
        parts = value.split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    if ioc_type == "domain":
        return "." in value and " " not in value and len(value) <= 253
    if ioc_type == "email":
        return "@" in value and " " not in value
    if ioc_type == "url":
        return value.startswith(("http://", "https://"))
    if ioc_type in ("sha256", "sha1", "md5"):
        lengths = {"sha256": 64, "sha1": 40, "md5": 32}
        return len(value) == lengths[ioc_type] and all(c in "0123456789abcdef" for c in value)
    return True