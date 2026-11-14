"""Identity correlation annotator.

Runs before detection so identity rules can use cross-session context. Works from any
auth telemetry carrying `user`, `outcome` and optional `geo_country` — no external
geolocation database is bundled (documented limitation; the IdP/edge sensor is expected
to attach geo fields).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.event import Event

IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 120


class IdentityEngine:
    def annotate(self, event: Event, db: Session) -> dict:
        """Mutate the event's raw view with cross-session identity context. Returns the annotations."""
        p = event.raw or {}
        if event.class_name != "authentication":
            return {}
        if str(p.get("outcome", "")).lower() != "success":
            return {}
        user = p.get("user") or event.user
        country_now = (p.get("geo_country") or "").upper()
        if not user or not country_now:
            return {}

        previous = (
            db.execute(
                select(Event)
                .where(
                    Event.class_name == "authentication",
                    Event.user == user,
                    Event.time < event.time,
                )
                .order_by(Event.time.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if previous is None:
            return {}
        prev_raw = previous.raw or {}
        prev_country = str(prev_raw.get("geo_country", "")).upper()
        if not prev_country or prev_country == country_now:
            return {}

        minutes = 0.0
        try:
            minutes = (event.time - previous.time).total_seconds() / 60
        except Exception:
            minutes = 0.0
        if minutes > IMPOSSIBLE_TRAVEL_WINDOW_MINUTES:
            return {}

        annotations = {
            "session_geo_change": "true",
            "geo_country_present": "true",
            "geo_country": country_now,
            "prev_geo_country": prev_country,
        }
        raw = dict(p)
        raw["_derived"] = {**(raw.get("_derived") or {}), **annotations}
        event.raw = raw
        return annotations

    def health(self) -> dict:
        return {"status": "ok", "signals": ["successive_login_geo_change"]}


identity_engine = IdentityEngine()