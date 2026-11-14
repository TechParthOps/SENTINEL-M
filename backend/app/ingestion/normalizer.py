"""Normalization pipeline: raw source events -> OCSF-aligned canonical events.

Phase-1 source types: auth, process, network, dns, file, http.
Unknown types are preserved verbatim as class `generic` — never dropped (Part 16).
Detection, correlation and the UI only ever see canonical events.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone

# class_name -> (class_uid OCSF-style, default severity)
CLASS_MAP: dict[str, tuple[str, int]] = {
    "auth": ("authentication", "3002", 1),
    "process": ("process_activity", "1007", 1),
    "network": ("network_activity", "4001", 1),
    "dns": ("dns_activity", "4003", 1),
    "file": ("file_activity", "1001", 1),
    "http": ("web_resource_access_activity", "4002", 1),
}
GENERIC_CLASS = ("generic", "9998", 1)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_EXTRACTED_HOST_IN_URL = re.compile(r"^[a-z]+://([^/:\s]+)", re.IGNORECASE)


def _ip_observable(value) -> dict | None:
    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return {"type": "ipv4", "value": str(value).strip()}


def _extract_domains(*texts: str) -> list[str]:
    found: list[str] = []
    for text in texts:
        if not text:
            continue
        for match in _DOMAIN_RE.findall(str(text).lower()):
            if match not in found:
                found.append(match)
    return found


def _parse_time(raw: str | None) -> datetime:
    """Naive-UTC datetimes throughout the pipeline (SQLite has no tz type)."""
    if raw:
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        except ValueError:
            pass
    return datetime.now(timezone.utc).replace(tzinfo=None)


def shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits/char (0..~6 for base32/base64)."""
    if not text:
        return 0.0
    from collections import Counter
    from math import log2

    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * log2(c / length) for c in counts.values())


def _derived_fields(ev, p: dict) -> dict:
    """Phase-2 derived metrics attached to the raw view for rule evaluation.

    Kept deterministic and cheap (no network, no models): DNS label entropy class,
    extent-of-recorded volume fields. Detection rules consume these via `where`.
    """
    derived: dict[str, str | int | float] = {}
    query = str(p.get("dns_query", ""))
    if query:
        first_label = query.split(".")[0]
        ent = shannon_entropy(first_label)
        derived["dns_label_len"] = len(first_label)
        derived["dns_label_entropy"] = round(ent, 3)
        derived["dns_label_entropy_class"] = (
            "high" if ent >= 3.2 and len(first_label) >= 16 else
            "medium" if ent >= 2.6 and len(first_label) >= 12 else "low"
        )
        derived["dns_subdomain_depth"] = query.count(".") + (1 if query else 0)
    for field in ("bytes_out", "bytes_in"):
        try:
            if p.get(field) is not None:
                derived[field] = int(p[field])
        except (TypeError, ValueError):
            pass
    if p.get("nxdomain") is not None:
        derived["nxdomain"] = "true" if p.get("nxdomain") in (True, "true", "1", 1) else "false"
    if p.get("geo_country"):
        derived["geo_country_present"] = "true"
        derived["geo_country"] = str(p.get("geo_country")).upper()
    return derived


def normalize_event(source: dict, ev) -> dict:
    """Returns a canonical event dict ready for Event(**...) and detection."""
    class_name, class_uid, default_sev = CLASS_MAP.get(ev.type, GENERIC_CLASS)
    p = ev.payload or {}
    ts = _parse_time(ev.time)
    derived = _derived_fields(ev, p)

    host = p.get("host") or p.get("hostname")
    src_ip = p.get("src_ip") or p.get("source_ip")
    dst_ip = p.get("dst_ip") or p.get("dest_ip") or p.get("destination_ip")
    src_port = p.get("src_port")
    dst_port = p.get("dst_port") or p.get("dest_port")
    protocol = p.get("protocol")
    user = p.get("user") or p.get("username")
    action = p.get("action") or p.get("file_action") or p.get("outcome")
    message = p.get("message") or f"{class_name} event from {host or src_ip or 'unknown source'}"

    # ---- observables (trust-boundary: raw field values become typed indicators)
    observables: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def _add(obs: dict | None) -> None:
        if obs and (obs["type"], obs["value"]) not in seen:
            seen.add((obs["type"], obs["value"]))
            observables.append(obs)

    _add(_ip_observable(src_ip))
    _add(_ip_observable(dst_ip))
    for d in _extract_domains(str(p.get("dns_query", "")), message):
        _add({"type": "domain", "value": d})
    url = p.get("http_url") or p.get("url")
    if url:
        _add({"type": "url", "value": str(url)})
        m = _EXTRACTED_HOST_IN_URL.match(str(url))
        if m:
            _add({"type": "domain", "value": m.group(1).lower()})

    event_id = str(uuid.uuid4())
    return {
        "id": event_id,
        "event_uid": str(p.get("event_id", ""))[:127],
        "time": ts,
        "class_uid": class_uid,
        "class_name": class_name,
        "severity_id": int(p.get("severity_id", default_sev) or default_sev),
        "message": message[:1024],
        "host": str(host)[:255] if host else None,
        "src_ip": str(src_ip)[:45] if src_ip else None,
        "src_port": int(src_port) if str(src_port).isdigit() else None,
        "dst_ip": str(dst_ip)[:45] if dst_ip else None,
        "dst_port": int(dst_port) if str(dst_port).isdigit() else None,
        "protocol": str(protocol)[:16] if protocol else None,
        "user": str(user)[:128] if user else None,
        "action": str(action)[:64] if action else None,
        "source_product": str(source.get("product", "unknown"))[:64],
        "source_version": str(source.get("version", ""))[:32],
        "raw": {**p, "_derived": derived},
        "observables": observables,
    }


def event_public(ev) -> dict:
    """Serializable view used for WebSocket payloads and API responses."""
    return {
        "id": ev.id,
        "time": ev.time.isoformat() if hasattr(ev.time, "isoformat") else ev.time,
        "class_name": ev.class_name,
        "severity_id": ev.severity_id,
        "message": ev.message,
        "host": ev.host,
        "src_ip": ev.src_ip,
        "dst_ip": ev.dst_ip,
        "user": ev.user,
        "action": ev.action,
        "source_product": ev.source_product,
        "observables": ev.observables or [],
    }