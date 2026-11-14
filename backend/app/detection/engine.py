"""Rule engine: evaluates normalized events against declarative JSON rules.

Rule types:
  - threshold: group events by `group_by` within a sliding window; fire at `min_count`
               (optionally counting DISTINCT values of `distinct_field`).
  - pattern:   all regexes in `patterns` must match on the event view; entity from
               `entity_field`; identical signatures deduplicated for `cooldown_seconds`.

Alerts are created in the DB, correlated into incidents immediately, and published
on the event bus. Every rule is reproducible in tests (no randomness, no clock luck
beyond window/cooldown arithmetic).
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.bus import bus
from app.detection.rules import Rule

REPO_ROOT = Path(__file__).resolve().parents[3]
RULES_DIR = REPO_ROOT / "detection-rules"


def _load_rule_files() -> list[dict]:
    rules: list[dict] = []
    if RULES_DIR.is_dir():
        for path in sorted(RULES_DIR.glob("*.json")):
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                data["_source_file"] = path.name
                rules.append(data)
    return rules


class DetectionEngine:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.rules: list[Rule] = []
        self._load_rules()
        # in-memory correlation state (reset between tests by conftest)
        self._window: deque = deque()
        self._last_alert: dict[tuple[str, str], float] = {}
        self._last_sig: dict[str, float] = {}
        self.fired_counts: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------- rules
    def _load_rules(self) -> None:
        self.rules = []
        for data in _load_rule_files():
            try:
                self.rules.append(Rule.from_dict(data))
            except Exception as exc:  # a broken rule file must never kill the engine
                print(f"[detection] skipping invalid rule file: {exc}")

    def reload_rules(self) -> int:
        with self._lock:
            self._load_rules()
            return len(self.rules)

    def rules_public(self) -> list[dict]:
        return [r.to_public() for r in sorted(self.rules, key=lambda r: r.id)]

    # ------------------------------------------------------------- engine
    def evaluate(self, event, db: Session, actor: str = "system") -> list:
        """Evaluate one normalized Event row; returns alerts created (usually 0 or 1)."""
        alerts = []
        view = self._view(event)
        for rule in self.rules:
            try:
                alert = self._evaluate_rule(rule, view, event, db, actor)
            except Exception as exc:  # engine must be resilient
                print(f"[detection] rule {rule.id} evaluation error: {exc}")
                alert = None
            if alert is not None:
                alerts.append(alert)
        if alerts:
            db.commit()
        return alerts

    def _view(self, event) -> dict:
        raw = getattr(event, "raw", {}) or {}
        v = dict(raw)
        v.update(raw.get("_derived", {}))  # Phase-2 derived metrics (DNS entropy class, volumes)
        v["class_name"] = event.class_name
        v["event_id"] = event.id
        v["severity_id"] = event.severity_id
        v["host"] = event.host or v.get("host")
        v["src_ip"] = event.src_ip or v.get("src_ip")
        v["dst_ip"] = event.dst_ip or v.get("dst_ip")
        v["dst_port"] = event.dst_port if event.dst_port is not None else v.get("dst_port")
        v["user"] = event.user or v.get("user")
        v["action"] = event.action or v.get("action")
        v["time"] = event.time
        return v

    def _evaluate_rule(self, rule: Rule, view: dict, event, db: Session, actor: str):
        if rule.class_name and view.get("class_name") != rule.class_name:
            return None
        if not rule.where_matches(view):
            return None

        if rule.type == "threshold":
            key = rule.group_key(view)
            if key is None:
                return None
            now = time.time()
            self._window.append(
                {
                    "rule_id": rule.id,
                    "key": key,
                    "ts": now,
                    "event_id": view.get("event_id"),
                    "distinct": str(view.get(rule.distinct_field))
                    if rule.distinct_field
                    else None,
                }
            )
            if not rule.cooldown_over(self._last_alert.get((rule.id, key)), now):
                return None
            entries = [
                e
                for e in self._window
                if e["rule_id"] == rule.id
                and e["key"] == key
                and now - e["ts"] <= rule.window_seconds
            ]
            if not entries:
                return None
            if rule.distinct_field:
                distinct_values = {e["distinct"] for e in entries if e["distinct"] is not None}
                fired = len(distinct_values) >= rule.min_count
                count = len(distinct_values)
            else:
                fired = len(entries) >= rule.min_count
                count = len(entries)
            if not fired:
                return None
            evidence_ids = [e["event_id"] for e in entries]
            return self._fire(
                rule, view, db, actor,
                entity_key=key, evidence_ids=evidence_ids,
                extra={"count": count, "distinct": count},
                cooldown_key=(rule.id, key),
            )

        if rule.type == "pattern":
            matched_field, matched_value = rule.pattern_matches(view)
            if matched_field is None:
                return None
            entity = view.get(rule.entity_field)
            if entity is None:
                return None
            entity = str(entity)
            sig = f"{rule.id}::{hashlib.sha1(str(view.get(rule.signature_field, matched_value)).encode()).hexdigest()}"
            now = time.time()
            if not rule.cooldown_over(self._last_sig.get(sig), now):
                return None
            return self._fire(
                rule, view, db, actor,
                entity_key=entity, evidence_ids=[view.get("event_id")],
                extra={"match": str(matched_value)[:120]},
                sig=sig,
            )
        return None

    def _fire(self, rule: Rule, view: dict, db: Session, actor: str, *,
              entity_key: str, evidence_ids: list, extra: dict,
              cooldown_key: tuple | None = None, sig: str | None = None):
        now = time.time()
        if cooldown_key:
            self._last_alert[cooldown_key] = now
        if sig:
            self._last_sig[sig] = now
        self.fired_counts[rule.id] += 1

        from app.correlation.engine import correlation_engine
        from app.models.alert import Alert

        alert = Alert(
            id=str(uuid.uuid4()),
            time=view.get("time") or datetime.now(timezone.utc).replace(tzinfo=None),
            rule_id=rule.id,
            rule_title=rule.title,
            category=rule.category,
            severity_id=rule.severity_id,
            entity_key=entity_key,
            entity_type=rule.entity_type,
            attack_ids=list(rule.attack_ids),
            attack_tactics=list(rule.attack_tactics),
            evidence_event_ids=[e for e in evidence_ids if e],
            status="new",
            message=rule.render_message(extra),
            source_product=str(view.get("source_product", "")) or "",
        )
        db.add(alert)
        db.flush()
        correlation_engine.process_alert(alert, db, actor=actor)
        bus.publish("alerts", self._alert_public(alert))
        return alert

    @staticmethod
    def _alert_public(alert) -> dict:
        return {
            "id": alert.id,
            "time": alert.time.isoformat() if hasattr(alert.time, "isoformat") else alert.time,
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "category": alert.category,
            "severity_id": alert.severity_id,
            "entity_key": alert.entity_key,
            "attack_ids": list(alert.attack_ids or []),
            "status": alert.status,
            "message": alert.message,
            "incident_id": alert.incident_id,
        }

    # health
    def health(self) -> dict:
        return {"status": "ok", "rules_loaded": len(self.rules)}


detection_engine = DetectionEngine()