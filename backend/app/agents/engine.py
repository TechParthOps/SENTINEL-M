"""Autonomous investigation orchestrator (Phase 4) — deterministic, read-only agents.

Design contract:
  - Specialist agents are plain deterministic functions over the platform's own stores
    (events, alerts, incidents, assets, intel). No LLM is required; a future LLM narrator
    must hook in AFTER these deterministic steps and never gate them.
  - Agents are READ-ONLY: no response actions are available to them. Containment/response
    is Phase 5 behind an approval workflow — an agent physically cannot mutate state here.
  - Every collected fact becomes an Evidence row in a per-investigation SHA-256 hash chain.
  - Every step is bounded: a wall-clock budget per investigation; tasks exceeding it are
    marked `skipped`, never silently dropped.
  - Lifecycle events are published on the `agents` bus topic for the live UI / 3D office.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.models import AgentTask, Evidence, Investigation
from app.core.bus import bus
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.event import Event
from app.models.incident import Incident

INVESTIGATION_TIME_BUDGET_SECONDS = 10.0

SPECIALISTS = [
    ("alert_triage", "Collect and structure the triggering alert and its evidence events"),
    ("asset_context", "Look up the entity in the asset inventory"),
    ("intel_check", "Check evidence observables against active threat-intel indicators"),
    ("related_activity", "Find related alerts/incidents for the same entity"),
    ("synthesis", "Combine findings into a verdict with reasoning"),
]


def _publish(event_type: str, data: dict) -> None:
    bus.publish("agents", {"type": event_type, **data})


def _content_hash(kind: str, ref_id: str, content: dict, prev_hash: str, seq: int) -> str:
    blob = f"{seq}|{kind}|{ref_id}|{prev_hash}|".encode() + str(
        sorted((k, str(v)) for k, v in content.items())
    ).encode()
    return hashlib.sha256(blob).hexdigest()


class Orchestrator:
    def start_investigation(
        self, db: Session, subject_type: str, subject_id: str, actor: str
    ) -> Investigation:
        """Validate the subject, create the investigation record (tasks queued)."""
        if subject_type not in ("alert", "entity"):
            raise ValueError("subject_type must be 'alert' or 'entity'")
        if subject_type == "alert":
            alert = db.get(Alert, subject_id)
            if alert is None:
                raise LookupError("alert not found")
        inv = Investigation(
            id=str(uuid.uuid4()),
            subject_type=subject_type,
            subject_id=subject_id[:255],
            status="queued",
            created_by=actor[:128],
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)
        _publish("investigation.created", self._inv_public(inv))
        return inv

    def run(self, db: Session, inv: Investigation) -> Investigation:
        """Execute all specialist tasks. Called synchronously (agents are fast/read-only)."""
        inv.status = "running"
        db.commit()
        _publish("investigation.status_changed",
                 {**self._inv_public(inv), "status": "running"})

        deadline = time.monotonic() + INVESTIGATION_TIME_BUDGET_SECONDS
        findings: dict = {"alerts": [], "assets": [], "intel": [], "related": [], "events": []}
        over_budget = False
        for seq, (agent, description) in enumerate(SPECIALISTS):
            if over_budget or time.monotonic() > deadline:
                over_budget = True
                self._record_task(db, inv.id, seq, agent, description, "skipped", {}, [], 0,
                                  "investigation time budget exhausted")
                continue
            t0 = time.monotonic()
            task = AgentTask(
                id=str(uuid.uuid4()), investigation_id=inv.id, seq=seq,
                agent=agent, description=description[:255], status="completed",
            )
            _publish("agent.task_started",
                     {"investigation_id": inv.id, "task_id": task.id, "agent": agent})
            try:
                out, evidence = self._run_specialist(agent, db, inv)
                task.output = out
                task.evidence_ids = [e.id for e in evidence]
            except Exception as exc:  # a failing specialist must not fail the investigation
                out, evidence = {}, []
                task.status = "failed"
                task.error = f"{type(exc).__name__}: {exc}"[:512]
            task.duration_ms = int((time.monotonic() - t0) * 1000)
            if agent == "synthesis":
                findings = task.output
                inv.verdict = str(findings.get("verdict", "unknown"))
                inv.summary = str(findings.get("summary", ""))[:2048]
            db.add(task)
            db.commit()
            _publish("agent.task_completed",
                     {"investigation_id": inv.id, "task_id": task.id, "agent": agent,
                      "status": task.status, "evidence_count": len(task.evidence_ids)})

        inv.result = {"specialists": [a for a, _ in SPECIALISTS]}
        inv.status = "completed"
        inv.finished_at = datetime.utcnow()
        db.commit()
        _publish("investigation.completed", self._inv_public(inv))
        return inv

    # ------------------------------------------------------------- specialists
    def _run_specialist(self, agent: str, db: Session, inv: Investigation):
        if agent == "alert_triage":
            return self._alert_triage(db, inv)
        if agent == "asset_context":
            return self._asset_context(db, inv)
        if agent == "intel_check":
            return self._intel_check(db, inv)
        if agent == "related_activity":
            return self._related_activity(db, inv)
        if agent == "synthesis":
            return self._synthesis(db, inv)
        raise ValueError(f"unknown specialist {agent}")

    def _resolve_entity(self, db: Session, inv: Investigation) -> tuple[str | None, str, Alert | None]:
        alert = None
        if inv.subject_type == "alert":
            alert = db.get(Alert, inv.subject_id)
            entity = alert.entity_key if alert else None
        else:
            entity = inv.subject_id
        return entity, inv.subject_id, alert

    def _collect(self, db: Session, inv: Investigation, kind: str, ref_id: str, content: dict):
        last = (
            db.query(Evidence)
            .filter(Evidence.investigation_id == inv.id)
            .order_by(Evidence.seq.desc())
            .first()
        )
        seq = (last.seq + 1) if last else 1
        prev = last.sha256 if last else ""
        row = Evidence(
            id=str(uuid.uuid4()), investigation_id=inv.id, seq=seq, kind=kind,
            ref_id=str(ref_id)[:255], content=content,
            sha256=_content_hash(kind, ref_id, content, prev, seq), prev_hash=prev,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def _alert_triage(self, db: Session, inv: Investigation):
        if inv.subject_type != "alert":
            return {"skipped": "subject is an entity, not an alert"}, []
        alert = db.get(Alert, inv.subject_id)
        out = {
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "severity_id": alert.severity_id,
            "category": alert.category,
            "attack_ids": alert.attack_ids or [],
            "entity": alert.entity_key,
            "status": alert.status,
            "message": alert.message,
            "evidence_event_count": len(alert.evidence_event_ids or []),
        }
        ev_row = self._collect(db, inv, "alert", alert.id, out)
        events_out = []
        for eid in (alert.evidence_event_ids or [])[:20]:
            ev = db.get(Event, eid)
            if ev is None:
                continue
            data = {
                "id": ev.id, "time": ev.time.isoformat() if ev.time else None,
                "class": ev.class_name, "message": ev.message,
                "host": ev.host, "src_ip": ev.src_ip, "dst_ip": ev.dst_ip,
                "user": ev.user, "severity_id": ev.severity_id,
            }
            events_out.append(data)
            self._collect(db, inv, "event", ev.id, data)
        out["evidence_events"] = events_out
        return out, [ev_row]

    def _asset_context(self, db: Session, inv: Investigation):
        entity, _, _ = self._resolve_entity(db, inv)
        if not entity:
            return {"note": "no entity resolvable"}, []
        asset = db.query(Asset).filter(Asset.hostname == entity).first()
        out: dict
        if asset is None:
            out = {"hostname": entity, "present": False,
                   "note": "entity not in asset inventory (may be an external IP)"}
        else:
            out = {
                "present": True,
                "id": asset.id,
                "hostname": asset.hostname,
                "ip": asset.ip_address,
                "asset_type": asset.asset_type,
                "criticality": asset.criticality,
                "is_sample": bool(asset.sample),
            }
            self._collect(db, inv, "asset", str(asset.id), out)
        return out, []

    def _intel_check(self, db: Session, inv: Investigation):
        entity, _, alert = self._resolve_entity(db, inv)
        observables: list[tuple[str, str]] = []
        event_ids: list[str] = []
        if alert is not None:
            event_ids = list(alert.evidence_event_ids or [])
        else:
            rows = db.execute(
                select(Event.id).where(
                    (Event.src_ip == inv.subject_id) | (Event.host == inv.subject_id))
                .order_by(Event.time.desc()).limit(25)
            ).scalars().all()
            event_ids = list(rows)
        for eid in event_ids[:25]:
            ev = db.get(Event, eid)
            if ev is None:
                continue
            for obs in (ev.observables or []):
                value = str(obs.get("value", ""))
                otype = str(obs.get("type", ""))
                if value and otype:
                    observables.append((otype, value))
        if entity:
            observables.append(("host", entity))

        from app.intelligence.engine import intelligence_engine

        hits = []
        seen = set()
        for otype, value in observables[:60]:
            if (otype, value) in seen:
                continue
            seen.add((otype, value))
            for ind in intelligence_engine.lookup(db, otype, value, active_only=True):
                data = {
                    "observable_type": otype, "observable_value": value,
                    "indicator_id": ind.id, "indicator_value": ind.value,
                    "source": ind.source, "confidence": ind.confidence,
                    "tags": ind.tags or [],
                }
                hits.append(data)
                self._collect(db, inv, "intel", ind.id, data)
        return {"observables_checked": len(seen), "active_indicator_hits": hits}, []

    def _related_activity(self, db: Session, inv: Investigation):
        entity, _, alert = self._resolve_entity(db, inv)
        if not entity:
            return {"note": "no entity"}, []
        week_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=7)
        related_alerts = (
            db.query(Alert)
            .filter(Alert.entity_key == entity, Alert.id != inv.subject_id,
                    Alert.time >= week_ago)
            .order_by(Alert.time.desc()).limit(20).all()
        )
        out_alerts = []
        for a in related_alerts:
            data = {"id": a.id, "rule_id": a.rule_id, "severity_id": a.severity_id,
                    "time": a.time.isoformat() if a.time else None,
                    "incident_id": a.incident_id}
            out_alerts.append(data)
            self._collect(db, inv, "alert", a.id, data)
        candidates = (
            db.query(Incident)
            .filter(Incident.last_seen >= week_ago)
            .order_by(Incident.last_seen.desc())
            .limit(25)
            .all()
        )
        related_incidents = [inc for inc in candidates if entity in (inc.entity_keys or [])][:10]
        out_incidents = []
        for inc in related_incidents:
            data = {"id": inc.id, "title": inc.title,
                    "severity_id": inc.severity_id, "status": inc.status,
                    "attack_chain": inc.attack_chain}
            out_incidents.append(data)
            self._collect(db, inv, "incident", inc.id, data)
        return {"related_alerts_7d": out_alerts, "related_incidents_7d": out_incidents}, []

    def _synthesis(self, db: Session, inv: Investigation):
        # combine the deterministic outputs of the previous tasks (from DB, not memory)
        tasks = (
            db.query(AgentTask)
            .filter(AgentTask.investigation_id == inv.id, AgentTask.status == "completed")
            .order_by(AgentTask.seq).all()
        )
        outputs = {t.agent: t.output for t in tasks}
        intel = outputs.get("intel_check", {})
        related = outputs.get("related_activity", {})
        alert_info = outputs.get("alert_triage", {})

        hits = intel.get("active_indicator_hits") or []
        rel_alerts = related.get("related_alerts_7d") or []
        rel_incidents = related.get("related_incidents_7d") or []

        if hits:
            verdict = "malicious"
            reasons = [f"{len(hits)} active threat-intel indicator hit(s): "
                       + ", ".join(h["observable_value"] for h in hits[:3])]
        elif len(rel_alerts) >= 3 or rel_incidents:
            verdict = "suspicious"
            reasons = [f"{len(rel_alerts)} related alerts and {len(rel_incidents)} incidents "
                       f"for the same entity in the last 7 days"]
        elif rel_alerts or alert_info:
            verdict = "suspicious"
            reasons = ["single detection with limited corroborating activity — review recommended"]
        else:
            verdict = "unknown"
            reasons = ["no corroborating evidence found by available specialists"]

        summary = f"Verdict {verdict}: " + "; ".join(reasons)
        return {"verdict": verdict, "summary": summary, "reasons": reasons,
                "intel_hits": len(hits), "related_alerts": len(rel_alerts),
                "related_incidents": len(rel_incidents)}, []

    # ------------------------------------------------------------- queries
    def list_investigations(self, db: Session, limit: int = 50) -> list[dict]:
        rows = db.query(Investigation).order_by(Investigation.created_at.desc()).limit(limit).all()
        return [self._inv_public(r) for r in rows]

    def get(self, db: Session, inv_id: str) -> dict | None:
        inv = db.get(Investigation, inv_id)
        if inv is None:
            return None
        tasks = (
            db.query(AgentTask)
            .filter(AgentTask.investigation_id == inv_id)
            .order_by(AgentTask.seq).all()
        )
        out = self._inv_public(inv)
        out["tasks"] = [
            {
                "id": t.id, "seq": t.seq, "agent": t.agent, "description": t.description,
                "status": t.status, "output": t.output, "error": t.error,
                "evidence_count": len(t.evidence_ids or []), "duration_ms": t.duration_ms,
            }
            for t in tasks
        ]
        return out

    def evidence(self, db: Session, inv_id: str) -> dict | None:
        inv = db.get(Investigation, inv_id)
        if inv is None:
            return None
        rows = (
            db.query(Evidence)
            .filter(Evidence.investigation_id == inv_id)
            .order_by(Evidence.seq).all()
        )
        # verify the chain
        prev = ""
        chain_ok = True
        for r in rows:
            expected = _content_hash(r.kind, r.ref_id, r.content, prev, r.seq)
            if r.prev_hash != prev or r.sha256 != expected:
                chain_ok = False
                break
            prev = r.sha256
        return {
            "investigation_id": inv_id,
            "chain_valid": chain_ok,
            "count": len(rows),
            "evidence": [
                {"id": r.id, "seq": r.seq, "kind": r.kind, "ref_id": r.ref_id,
                 "content": r.content, "sha256": r.sha256, "prev_hash": r.prev_hash,
                 "collected_at": r.collected_at.isoformat() if r.collected_at else None}
                for r in rows
            ],
        }

    def _inv_public(self, inv: Investigation) -> dict:
        return {
            "id": inv.id, "subject_type": inv.subject_type, "subject_id": inv.subject_id,
            "status": inv.status, "verdict": inv.verdict, "summary": inv.summary,
            "error": inv.error, "created_by": inv.created_by,
            "created_at": inv.created_at.isoformat() if inv.created_at else None,
            "finished_at": inv.finished_at.isoformat() if inv.finished_at else None,
        }

    def health(self) -> dict:
        return {
            "status": "ok",
            "specialists": [a for a, _ in SPECIALISTS],
            "mode": "deterministic (no LLM required; LLM narration is an optional post-hook)",
            "permissions": "read-only (no response actions available to agents)",
            "time_budget_seconds": INVESTIGATION_TIME_BUDGET_SECONDS,
        }


orchestrator = Orchestrator()
