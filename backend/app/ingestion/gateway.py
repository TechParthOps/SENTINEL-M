"""Ingestion gateway: validate -> normalize -> persist -> detect -> correlate -> broadcast."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core import audit
from app.core.bus import bus
from app.detection.engine import detection_engine
from app.ingestion.normalizer import event_public, normalize_event
from app.models.asset import Asset
from app.models.event import Event


def register_asset_from_event(db: Session, host: str | None, src_ip: str | None) -> None:
    """Auto-register inventory from telemetry (never fakes, never overwrites manual assets)."""
    if not host:
        return
    now = datetime.now(timezone.utc)
    asset = db.query(Asset).filter(Asset.hostname == host).first()
    if asset is None:
        asset_type = (
            "domain_controller" if host.lower().startswith(("dc-", "ad-")) else "workstation"
        )
        asset = Asset(
            hostname=host,
            asset_type=asset_type,
            ip_address=src_ip,
            auto_registered=True,
            sample=False,
            last_seen=now,
        )
        db.add(asset)
    asset.last_seen = now
    db.flush()


def ingest_events(db: Session, payload, actor: str = "system") -> dict:
    """payload: IngestRequest. Returns {'accepted': n, 'event_ids': [...]}."""
    accepted = 0
    event_ids: list[str] = []
    alerts_created = 0
    incidents_touched = 0
    for ev in payload.events:
        norm = normalize_event(payload.source, ev)
        event = Event(**norm)
        db.add(event)
        db.flush()  # id + row exist before detection so evidence references resolve
        register_asset_from_event(db, event.host, event.src_ip)
        created = detection_engine.evaluate(event, db, actor=actor)
        alerts_created += len(created)
        for a in created:
            incidents_touched += 1 if a.incident_id else 0
        bus.publish("events", event_public(event))
        event_ids.append(event.id)
        accepted += 1
    db.commit()
    audit.record(
        "events.ingest",
        actor=actor,
        details={
            "accepted": accepted,
            "source": payload.source.get("product", "unknown") if payload.source else "unknown",
            "alerts": alerts_created,
            "batch_id": uuid.uuid4().hex[:12],
        },
    )
    return {
        "accepted": accepted,
        "event_ids": event_ids,
        "alerts_created": alerts_created,
        "incidents_touched": incidents_touched,
    }