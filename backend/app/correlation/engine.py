"""Correlation engine (ADR-006): alerts -> incidents with narratives."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.bus import bus
from app.models.alert import Alert
from app.models.incident import Incident


class CorrelationEngine:
    """Groups alerts by entity within an open-incident window and escalates attack chains."""

    def process_alert(self, alert: Alert, db: Session, actor: str = "system") -> Incident | None:
        incident = self._find_open_incident(db, alert)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if incident is None:
            incident = self._create_incident(alert, now)
            db.add(incident)
        else:
            self._extend_incident(incident, alert, now)
        db.flush()
        alert.incident_id = incident.id
        db.flush()
        bus.publish("incidents", self._incident_public(incident))
        return incident

    # ------------------------------------------------------------------
    def _find_open_incident(self, db: Session, alert: Alert) -> Incident | None:
        rows = (
            db.execute(
                select(Incident)
                .where(Incident.status == "open")
                .order_by(Incident.last_seen.desc())
                .limit(200)
            )
            .scalars()
            .all()
        )
        for inc in rows:
            if alert.entity_key in (inc.entity_keys or []):
                return inc
        return None

    def _create_incident(self, alert: Alert, now: datetime) -> Incident:
        attacks = list(dict.fromkeys(alert.attack_ids or []))
        chain = len(attacks) >= 2
        inc = Incident(
            id=str(uuid.uuid4()),
            title=f"{alert.rule_title} on {alert.entity_key}",
            summary="",
            category="potential_intrusion" if chain else alert.category,
            severity_id=alert.severity_id,
            entity_keys=[alert.entity_key],
            attack_ids=attacks,
            attack_chain=chain,
            alert_ids=[alert.id],
            timeline=[self._timeline_entry(alert)],
            status="open",
            first_seen=alert.time or now,
            last_seen=now,
        )
        self._refresh_narrative(inc)
        return inc

    def _extend_incident(self, inc: Incident, alert: Alert, now: datetime) -> None:
        inc.alert_ids = list(inc.alert_ids or []) + [alert.id]
        inc.timeline = list(inc.timeline or []) + [self._timeline_entry(alert)]
        inc.entity_keys = sorted(
            set(inc.entity_keys or []) | {alert.entity_key}
        )
        inc.attack_ids = sorted(set(inc.attack_ids or []) | set(alert.attack_ids or []))
        inc.attack_chain = len(inc.attack_ids) >= 2
        max_sev = max(alert.severity_id, inc.severity_id or 0)
        # attack chains escalate one severity step for technique diversity (explainable, capped)
        inc.severity_id = min(6, max_sev + 1) if inc.attack_chain else max_sev
        if inc.attack_chain:
            inc.category = "potential_intrusion"
        inc.last_seen = now
        inc.updated_at = now
        self._refresh_narrative(inc)

    # ------------------------------------------------------------------
    @staticmethod
    def _timeline_entry(alert: Alert) -> dict:
        return {
            "t": (alert.time or datetime.now(timezone.utc).replace(tzinfo=None)).isoformat(),
            "alert_id": alert.id,
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "entity_key": alert.entity_key,
            "severity_id": alert.severity_id,
            "attack_ids": list(alert.attack_ids or []),
            "evidence_event_ids": len(alert.evidence_event_ids or []),
        }

    def _refresh_narrative(self, inc: Incident) -> None:
        entities = ", ".join(inc.entity_keys or [])
        techniques = ", ".join(inc.attack_ids or [])
        n = len(inc.alert_ids or [])
        if inc.attack_chain:
            inc.summary = (
                f"Correlated attack chain on {entities}: {n} linked alerts across techniques "
                f"{techniques}. Distinct ATT&CK techniques on the same entity within the "
                f"correlation window indicate a potential intrusion sequence rather than "
                f"isolated findings. Severity escalated for technique diversity."
            )
        else:
            inc.summary = (
                f"{n} alert(s) on {entities} involving {techniques}. "
                f"No multi-stage correlation in the current window."
            )

    @staticmethod
    def _incident_public(inc: Incident) -> dict:
        return {
            "id": inc.id,
            "title": inc.title,
            "category": inc.category,
            "severity_id": inc.severity_id,
            "status": inc.status,
            "entity_keys": list(inc.entity_keys or []),
            "attack_ids": list(inc.attack_ids or []),
            "attack_chain": inc.attack_chain,
        }

    def health(self) -> dict:
        return {"status": "ok"}


correlation_engine = CorrelationEngine()