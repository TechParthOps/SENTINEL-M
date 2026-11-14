"""Threat intelligence engine (Part 7 + Phase 2).

Responsibilities:
  1. Load indicators from local STIX 2.1 JSON feeds (offline, no network required).
  2. Deduplicate by (type, value); keep provenance (source, confidence, validity window).
  3. Enrich incoming events against *active, non-expired* indicators and create
     INTEL-IOC-001 alerts with evidence references.
  4. Source reputation: only indicators with confidence >= min_confidence create alerts;
     expired/future indicators never match (indicator aging, false-positive management).

Untrusted public feeds never gain automatic authority — every alert cites the feed,
its confidence and the observed event.
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.bus import bus
from app.core.config import settings
from app.intelligence.models import Indicator
from app.intelligence.stix import parse_bundle
from app.models.alert import Alert

REPO_ROOT = Path(__file__).resolve().parents[3]
FEEDS_DIR = REPO_ROOT / "intel-feeds"
MIN_ALERT_CONFIDENCE = 60
_HIGH_CONFIDENCE = 80
_COLUMNS = {c.name for c in Indicator.__table__.columns}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def feeds_dir() -> Path:
    """Feed location is configurable for test isolation (SENTINEL_TEST_INTEL_FEEDS_DIR)."""
    if settings.test_intel_feeds_dir:
        return Path(settings.test_intel_feeds_dir)
    return FEEDS_DIR


def _to_model(ind: dict) -> Indicator:
    """Map a parsed indicator dict onto the ORM model, filling required fields."""
    fields = {k: v for k, v in ind.items() if k in _COLUMNS and v is not None}
    fields.setdefault("id", str(uuid.uuid4()))
    fields.setdefault("added_at", _now())
    fields.setdefault("source", "unknown")
    fields.setdefault("source_type", "feed")
    fields.setdefault("confidence", 50)
    fields.setdefault("reliability", "C")
    return Indicator(**fields)


class IntelEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.last_import_stats: dict = {}
        self.min_alert_confidence = MIN_ALERT_CONFIDENCE

    # ------------------------------------------------------------- loading
    def import_indicators(self, db: Session, indicators: list[dict]) -> dict:
        """Insert parsed indicators, deduplicating by (type, value)."""
        imported = deduped = 0
        for ind in indicators:
            exists = (
                db.execute(
                    select(Indicator).where(
                        Indicator.type == ind["type"], Indicator.value == ind["value"]
                    )
                )
                .scalars()
                .first()
            )
            if exists is not None:
                deduped += 1
                continue
            db.add(_to_model(ind))
            imported += 1
        db.commit()
        return {"imported": imported, "duplicates": deduped, "deduplicated": deduped, "parsed": len(indicators)}

    def load_feeds(self, db: Session, directory: Path | None = None) -> dict:
        """Import every *.json STIX bundle in the feeds directory. Idempotent by (type, value)."""
        directory = directory or feeds_dir()
        loaded = skipped = 0
        sources: list[dict] = []
        if not directory.is_dir():
            self.last_import_stats = {"files": 0, "imported": 0, "skipped": 0, "sources": []}
            return self.last_import_stats
        for path in sorted(directory.glob("*.json")):
            loaded += 1
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    bundle = json.load(fh)
                indicators = parse_bundle(bundle, default_source=path.stem)
            except Exception as exc:
                skipped += 1
                sources.append({"file": path.name, "error": str(exc)[:200]})
                continue
            result = self.import_indicators(db, indicators)
            sources.append({"file": path.name, **result})
        stats = {
            "files": loaded,
            "skipped": skipped,
            "sources": sources,
            "at": _now().isoformat(),
            "total_imported": sum(s.get("imported", 0) for s in sources),
            "total_deduplicated": sum(s.get("deduplicated", 0) for s in sources),
        }
        self.last_import_stats = stats
        return stats

    # ------------------------------------------------------------- lookup
    def lookup(self, db: Session, ioc_type: str, value: str, active_only: bool = True) -> list[Indicator]:
        stmt = select(Indicator).where(
            Indicator.type == ioc_type, Indicator.value == str(value).strip().lower()
        )
        rows = db.execute(stmt).scalars().all()
        if active_only:
            now = _now()
            rows = [r for r in rows if r.status(now) == "active"]
        return rows

    def enrich(self, event, db: Session, actor: str = "system") -> list[dict]:
        """Correlate an event's observables against active indicators.

        Returns hit summaries; creates INTEL-IOC-001 alerts for indicators at or above
        `min_alert_confidence` with evidence references, then correlates them like any
        other alert.
        """
        if not event.observables:
            return []
        hits: list[dict] = []
        now = _now()
        for obs in event.observables:
            indicator = self._match(db, obs)
            if indicator is None:
                continue
            indicator.last_seen = now
            indicator.times_observed = (indicator.times_observed or 0) + 1
            hit = {
                "indicator_id": indicator.id,
                "type": indicator.type,
                "value": indicator.value,
                "source": indicator.source,
                "confidence": indicator.confidence,
                "reliability": indicator.reliability,
                "valid_until": indicator.valid_until.isoformat() if indicator.valid_until else None,
                "tags": indicator.tags or [],
            }
            hits.append(hit)
            if indicator.confidence >= self.min_alert_confidence:
                self._create_intel_alert(event, indicator, db, actor)
        if hits:
            raw = dict(event.raw or {})
            raw["_intel"] = hits
            event.raw = raw
            enriched = dict(event.enriched or {})
            enriched["intel"] = hits
            event.enriched = enriched
            db.commit()
            bus.publish("intel", {"event_id": event.id, "hits": hits})
        return hits

    def _match(self, db: Session, obs: dict) -> Indicator | None:
        otype, ovalue = obs.get("type"), str(obs.get("value", "")).strip().lower()
        if otype not in ("ipv4", "domain", "url"):
            return None
        candidates = self.lookup(db, otype, ovalue, active_only=True)
        if candidates:
            return max(candidates, key=lambda i: i.confidence)
        # domain sub-matching: a queried subdomain of a blacklisted domain also matches
        if otype == "domain" and "." in ovalue:
            parent = ovalue.split(".", 1)[1] if ovalue.count(".") >= 2 else None
            if parent:
                candidates = self.lookup(db, "domain", parent, active_only=True)
                if candidates:
                    return max(candidates, key=lambda i: i.confidence)
        return None

    def _create_intel_alert(self, event, indicator: Indicator, db: Session, actor: str) -> Alert:
        from app.correlation.engine import correlation_engine

        severity = 4 if indicator.confidence >= _HIGH_CONFIDENCE else 3
        alert = Alert(
            id=str(uuid.uuid4()),
            time=event.time or _now(),
            rule_id="INTEL-IOC-001",
            rule_title="Communication with known threat indicator",
            category="threat_intelligence",
            severity_id=severity,
            entity_key=indicator.value,
            entity_type=indicator.type,
            attack_ids=[],
            attack_tactics=[],
            evidence_event_ids=[event.id],
            status="new",
            message=(
                f"Event {event.class_name} on {event.host or event.src_ip or 'unknown'} references "
                f"{indicator.type} indicator {indicator.value} (source {indicator.source}, "
                f"confidence {indicator.confidence}, reliability {indicator.reliability})."
            ),
            source_product=event.source_product,
            dedup_sig=f"INTEL-IOC-001::{indicator.type}::{indicator.value}",
        )
        db.add(alert)
        db.flush()
        correlation_engine.process_alert(alert, db, actor=actor)
        bus.publish("alerts", {
            "id": alert.id,
            "time": alert.time.isoformat() if hasattr(alert.time, "isoformat") else alert.time,
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "category": alert.category,
            "severity_id": alert.severity_id,
            "entity_key": alert.entity_key,
            "attack_ids": [],
            "status": alert.status,
            "message": alert.message,
            "incident_id": alert.incident_id,
        })
        return alert

    # ------------------------------------------------------------- stats
    def feed_status(self, db: Session) -> dict:
        rows = db.execute(select(Indicator)).scalars().all()
        now = _now()
        by_status: dict[str, int] = {}
        by_source: dict[str, int] = {}
        for r in rows:
            by_status[r.status(now)] = by_status.get(r.status(now), 0) + 1
            by_source[r.source] = by_source.get(r.source, 0) + 1
        return {
            "total": len(rows),
            "by_status": by_status,
            "by_source": by_source,
            "last_import": self.last_import_stats,
            "min_alert_confidence": self.min_alert_confidence,
        }

    def health(self) -> dict:
        return {"status": "ok", "feeds_dir": str(FEEDS_DIR)}


intelligence_engine = IntelEngine()