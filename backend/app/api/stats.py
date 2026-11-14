"""Overview statistics API — every metric traces back to real rows."""
from __future__ import annotations

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import CurrentUser
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.event import Event
from app.models.incident import Incident

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/overview")
def overview(user: CurrentUser, db: Session = Depends(get_db)):
    import datetime as dt

    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    window_start = now - dt.timedelta(minutes=30)
    day_start = now - dt.timedelta(hours=24)

    # ---- events per minute for the last 30 minutes (always 30 buckets)
    events_30m = (
        db.query(Event.time).filter(Event.time >= window_start).order_by(Event.time).all()
    )
    buckets: Counter[int] = Counter()
    for (ts,) in events_30m:
        # bucket index 0..29 counting backwards from now
        minutes_ago = int((now - ts).total_seconds() // 60)
        if 0 <= minutes_ago < 30:
            buckets[29 - minutes_ago] += 1
    timeline = [{"t": (window_start + dt.timedelta(minutes=i + 1)).isoformat(), "count": buckets.get(i, 0)} for i in range(30)]

    events_total = db.query(func.count(Event.id)).scalar() or 0
    events_per_sec_30m = round(events_total and sum(b["count"] for b in timeline) / 1800, 4)

    alerts_by_status = dict(
        db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    )
    incidents_open = (
        db.query(func.count(Incident.id)).filter(Incident.status == "open").scalar() or 0
    )
    incidents_critical = (
        db.query(func.count(Incident.id)).filter(Incident.severity_id >= 5).scalar() or 0
    )

    top_rules = (
        db.query(Alert.rule_id, func.count(Alert.id))
        .filter(Alert.time >= day_start)
        .group_by(Alert.rule_id)
        .order_by(func.count(Alert.id).desc())
        .limit(8)
        .all()
    )

    class_distribution = dict(
        db.query(Event.class_name, func.count(Event.id)).group_by(Event.class_name).all()
    )

    # Phase 2: threat-intelligence posture (live counts, no simulated feeds)
    from app.intelligence.engine import intelligence_engine

    intel_status = intelligence_engine.feed_status(db)
    intel_hits_24h = (
        db.query(func.count(Alert.id))
        .filter(Alert.rule_id == "INTEL-IOC-001", Alert.time >= day_start)
        .scalar() or 0
    )

    return {
        "generated_at": now.isoformat(),
        "events": {
            "total": events_total,
            "per_second_30m": events_per_sec_30m,
            "timeline_30m": timeline,
            "by_class": class_distribution,
        },
        "alerts": {
            "total": db.query(func.count(Alert.id)).scalar() or 0,
            "by_status": alerts_by_status,
            "open": alerts_by_status.get("new", 0) + alerts_by_status.get("ack", 0),
        },
        "incidents": {
            "total": db.query(func.count(Incident.id)).scalar() or 0,
            "open": incidents_open,
            "critical": incidents_critical,
        },
        "assets": {
            "total": db.query(func.count(Asset.id)).scalar() or 0,
            "sample": db.query(func.count(Asset.id)).filter(Asset.sample.is_(True)).scalar() or 0,
            "auto_registered": (
                db.query(func.count(Asset.id)).filter(Asset.auto_registered.is_(True)).scalar() or 0
            ),
            "telemetry_seen": (
                db.query(func.count(Asset.id)).filter(Asset.last_seen.isnot(None)).scalar() or 0
            ),
        },
        "top_rules_24h": [{"rule_id": r, "count": c} for r, c in top_rules],
        "intel": {
            "indicators_total": intel_status["total"],
            "indicators_active": intel_status["by_status"].get("active", 0),
            "indicators_expired": intel_status["by_status"].get("expired", 0),
            "feeds": list(intel_status["by_source"].keys()),
            "event_hits_24h": intel_hits_24h,
        },
    }