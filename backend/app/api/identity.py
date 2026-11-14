"""Identity security API: authentication telemetry summary + identity detections."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import CurrentUser
from app.models.alert import Alert
from app.models.event import Event

router = APIRouter(prefix="/identity", tags=["identity"])

IDENTITY_RULES = ("ID-IMPOSSIBLE-TRAVEL-001", "AUTH-BRUTEFORCE-001",
                  "AUTH-SUSPICIOUS-LOGON-003", "AUTH-PASSWORDSPRAY-002")


@router.get("/summary")
def summary(user: CurrentUser, db: Session = Depends(get_db)):
    """Live identity posture from ingested auth telemetry (no simulated accounts)."""
    day_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
    auth = db.query(Event).filter(Event.class_name == "authentication")

    total_24h = auth.filter(Event.time >= day_start).count()
    distinct_users = (
        db.query(func.count(func.distinct(Event.user)))
        .filter(Event.class_name == "authentication", Event.user.isnot(None))
        .scalar() or 0
    )
    # Outcome breakdown is read from the raw payload (normalizer keeps vendor fields intact).
    rows = (
        db.execute(
            select(Event.raw).where(Event.class_name == "authentication", Event.time >= day_start)
        )
        .scalars()
        .all()
    )
    successes = failures = geo_changes = 0
    users_with_geo = set()
    for raw in rows:
        outcome = str((raw or {}).get("outcome", "")).lower()
        if outcome == "success":
            successes += 1
        elif outcome:
            failures += 1
        if (raw or {}).get("_derived", {}).get("session_geo_change") == "true":
            geo_changes += 1
        u = (raw or {}).get("user") or (raw or {}).get("username")
        if u:
            users_with_geo.add(str(u))
    identity_alerts_24h = (
        db.query(func.count(Alert.id))
        .filter(Alert.rule_id.in_(IDENTITY_RULES), Alert.time >= day_start)
        .scalar() or 0
    )
    return {
        "auth_events_24h": total_24h,
        "successes_24h": successes,
        "failures_24h": failures,
        "distinct_users": distinct_users,
        "geo_change_events_24h": geo_changes,
        "users_with_geo_context": len(users_with_geo),
        "identity_alerts_24h": identity_alerts_24h,
        "limitation": (
            "Impossible-travel analysis requires the IdP/edge sensor to attach geo_country; "
            "no bundled geolocation database (documented limitation)."
        ),
    }
