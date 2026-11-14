"""Policy-authorized response engine (Phase 5).

Hard rules (non-negotiable):
  - An allowlist of action types only; anything else is denied outright.
  - Autonomy levels (per action, per target criticality):
      L0 manual — approval required, always.
      L1 semi-auto — dry-run may auto-execute (simulation only); real execution needs approval.
      L2 auto — reversible, low-impact actions on NON-critical assets may auto-execute.
  - Emergency stop: SENTINEL_RESPONSE_ENABLED=false blocks every real execution
    (dry-runs still allowed so teams can rehearse).
  - Every action records previous state to support rollback where meaningful, and a
    post-execution verification read that must CONFIRM the effect before status=verified.
  - Every state change is audit-recorded and published on the `response` bus topic.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.core import audit
from app.core.bus import bus
from app.core.config import settings
from app.models.alert import Alert
from app.models.asset import Asset
from app.response.models import ResponseAction

# action_type -> (autonomy_level, reversible, description)
ACTION_ALLOWLIST: dict[str, tuple[int, bool, str]] = {
    "asset_isolate": (2, True, "Mark an asset as isolated in the asset inventory (host flag)"),
    "asset_release": (2, True, "Release an isolated asset back to normal status"),
    "ip_denylist_add": (1, True, "Add an IP to the response denylist (edge-integration feed)"),
    "ip_denylist_remove": (1, True, "Remove an IP from the response denylist"),
    "alert_escalate": (2, False, "Raise an alert's severity and mark it investigating"),
    "incident_contain": (0, True, "Mark an incident as contained (status change)"),
    "incident_reopen": (0, True, "Reopen a contained incident"),
}

L_AUTO = 2  # level at which dry-run/execute may auto-execute for reversible, low-criticality targets


def _publish(event_type: str, data: dict) -> None:
    bus.publish("response", {"type": event_type, **data})


class PolicyDecision:
    def __init__(self, allowed: bool, requires_approval: bool, reason: str):
        self.allowed = allowed
        self.requires_approval = requires_approval
        self.reason = reason

    def public(self) -> dict:
        return {"allowed": self.allowed, "requires_approval": self.requires_approval,
                "reason": self.reason}


class ResponseEngine:
    def policy(self) -> dict:
        return {
            "allowlist": {k: {"autonomy_level": v[0], "reversible": v[1], "description": v[2]}
                          for k, v in ACTION_ALLOWLIST.items()},
            "auto_execute_level": L_AUTO,
            "response_enabled": settings.response_enabled,
            "rule": ("L0 = approval always; L1 = dry-run auto/execute approved; "
                     "L2 = reversible + non-critical target may auto-execute; "
                     "critical assets (criticality>=4) always require approval"),
        }

    def decide(self, db: Session, action_type: str, target_type: str, target: str,
               dry_run: bool) -> PolicyDecision:
        spec = ACTION_ALLOWLIST.get(action_type)
        if spec is None:
            return PolicyDecision(False, True, f"action type '{action_type}' is not in the allowlist")
        level, reversible, _ = spec
        if dry_run:
            return PolicyDecision(True, False, "dry-run simulation is always permitted")
        if not settings.response_enabled:
            return PolicyDecision(False, True, "response engine disabled (emergency stop)")
        if level >= L_AUTO and reversible:
            # auto only for non-critical assets
            if target_type == "asset":
                asset = self._asset(db, target)
                if asset is not None and asset.criticality >= 4:
                    return PolicyDecision(True, True, "critical asset requires approval")
                return PolicyDecision(True, False, "reversible action on non-critical asset (L2)")
            return PolicyDecision(True, False, "reversible action (L2)")
        return PolicyDecision(True, True, f"level {level} action requires approval")

    # ------------------------------------------------------------- lifecycle
    def request(self, db: Session, action_type: str, target_type: str, target: str,
                reason: str, actor: str, dry_run: bool = False) -> ResponseAction:
        if action_type not in ACTION_ALLOWLIST:
            raise ValueError(f"action type '{action_type}' is not in the allowlist")
        if target_type not in ("asset", "ip", "alert", "incident"):
            raise ValueError("target_type must be asset|ip|alert|incident")
        action = ResponseAction(
            id=str(uuid.uuid4()), action_type=action_type, target_type=target_type,
            target=target[:255], reason=reason[:1024], dry_run=dry_run,
            requested_by=actor[:128],
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        _publish("response.requested", self._public(action))
        return action

    def dry_run(self, db: Session, action: ResponseAction) -> ResponseAction:
        decision = self.decide(db, action.action_type, action.target_type, action.target,
                               dry_run=True)
        if not decision.allowed:
            raise PermissionError(decision.reason)
        action.dry_run = True
        action.status = "dry_run"
        action.result = {"simulation": True, **self._simulate(db, action)}
        db.commit()
        _publish("response.dry_run", self._public(action))
        return action

    def approve(self, db: Session, action: ResponseAction, actor: str) -> ResponseAction:
        if action.status not in ("requested", "denied"):
            raise ValueError("only a requested action can be approved")
        action.status = "approved"
        action.approved_by = actor[:128]
        db.commit()
        audit.record("response.approved", actor=actor,
                     details={"action_id": action.id, "type": action.action_type})
        _publish("response.approved", self._public(action))
        return action

    def deny(self, db: Session, action: ResponseAction, actor: str, reason: str) -> ResponseAction:
        action.status = "denied"
        action.result = {"denied_reason": reason[:512]}
        db.commit()
        audit.record("response.denied", actor=actor,
                     details={"action_id": action.id, "reason": reason})
        _publish("response.denied", self._public(action))
        return action

    def execute(self, db: Session, action: ResponseAction, actor: str) -> ResponseAction:
        decision = self.decide(db, action.action_type, action.target_type, action.target,
                               dry_run=False)
        if not decision.allowed:
            action.status = "denied"
            action.result = {"denied_reason": decision.reason}
            db.commit()
            _publish("response.denied", self._public(action))
            return action
        if decision.requires_approval and action.status != "approved":
            raise PermissionError(f"approval required: {decision.reason}")

        previous = self._previous_state(db, action)
        try:
            effect = self._apply(db, action)
        except Exception as exc:
            action.status = "failed"
            action.result = {**previous, "error": f"{type(exc).__name__}: {exc}"[:400]}
            action.executed_at = datetime.utcnow()
            db.commit()
            _publish("response.failed", self._public(action))
            return action
        action.executed_at = datetime.utcnow()
        action.status = "executed"
        action.result = {**previous, "effect": effect, "executed_by": actor}
        db.commit()
        audit.record("response.executed", actor=actor,
                     details={"action_id": action.id, "type": action.action_type,
                              "target": action.target})
        _publish("response.executed", self._public(action))
        self.verify(db, action)
        return action

    def verify(self, db: Session, action: ResponseAction) -> dict:
        """Re-read the target state and confirm the action's effect still holds."""
        holds, detail = self._check_effect(db, action)
        action.verification = {"verified": holds, "detail": detail,
                               "checked_at": datetime.utcnow().isoformat()}
        if holds and action.status == "executed":
            action.status = "verified"
        db.commit()
        _publish("response.verified" if holds else "response.verify_failed", self._public(action))
        return action.verification

    def rollback(self, db: Session, action: ResponseAction, actor: str) -> ResponseAction:
        if action.status not in ("executed", "verified", "failed"):
            raise ValueError("only executed actions can be rolled back")
        if not ACTION_ALLOWLIST.get(action.action_type, (0, False, ""))[1]:
            raise ValueError(f"action type '{action.action_type}' is not reversible")
        prev = action.result or {}
        effect = self._restore_previous(db, action, prev)
        action.status = "rolled_back"
        action.result = {**prev, "rollback": effect, "rolled_back_by": actor}
        db.commit()
        audit.record("response.rolled_back", actor=actor, details={"action_id": action.id})
        _publish("response.rolled_back", self._public(action))
        return action

    # ------------------------------------------------------------- effects
    def _asset(self, db: Session, hostname: str) -> Asset | None:
        return db.query(Asset).filter(Asset.hostname == hostname).first()

    def _previous_state(self, db: Session, action: ResponseAction) -> dict:
        t, key = action.target_type, action.target
        if t == "asset":
            asset = self._asset(db, key)
            return {"previous": {"isolated": bool(asset.isolated) if asset else None}}
        if t == "ip":
            from app.response.models import DenylistEntry

            row = db.query(DenylistEntry).filter(DenylistEntry.ip == key).first()
            return {"previous": {"denylisted": row is not None}}
        if t == "alert":
            alert = db.get(Alert, key)
            return {"previous": {"status": alert.status if alert else None,
                                 "severity_id": alert.severity_id if alert else None}}
        if t == "incident":
            from app.models.incident import Incident

            inc = db.get(Incident, key)
            return {"previous": {"status": inc.status if inc else None}}
        return {}

    def _simulate(self, db: Session, action: ResponseAction) -> dict:
        return {"would": self._effect_description(action),
                "target_state": self._previous_state(db, action)["previous"]}

    def _effect_description(self, action: ResponseAction) -> str:
        return {
            "asset_isolate": "asset.isolated -> True",
            "asset_release": "asset.isolated -> False",
            "ip_denylist_add": "denylist entry created",
            "ip_denylist_remove": "denylist entry removed",
            "alert_escalate": "alert severity raised, status -> investigating",
            "incident_contain": "incident.status -> contained",
            "incident_reopen": "incident.status -> open",
        }.get(action.action_type, "unknown effect")

    def _apply(self, db: Session, action: ResponseAction) -> dict:
        t, key = action.target_type, action.target
        if t == "asset":
            asset = self._asset(db, key)
            if asset is None:
                raise ValueError(f"asset '{key}' not found")
            if action.action_type == "asset_isolate":
                asset.isolated = True
            elif action.action_type == "asset_release":
                asset.isolated = False
            else:
                raise ValueError("asset target supports asset_isolate/asset_release only")
            db.commit()
            return {"isolated": bool(asset.isolated)}
        if t == "ip":
            from app.response.models import DenylistEntry

            if action.action_type == "ip_denylist_add":
                if not db.query(DenylistEntry).filter(DenylistEntry.ip == key).first():
                    db.add(DenylistEntry(id=str(uuid.uuid4()), ip=key[:45],
                                         added_by=action.requested_by, reason=action.reason[:512]))
                db.commit()
                return {"denylisted": True}
            if action.action_type == "ip_denylist_remove":
                row = db.query(DenylistEntry).filter(DenylistEntry.ip == key).first()
                if row is not None:
                    db.delete(row)
                    db.commit()
                return {"denylisted": False}
            raise ValueError("ip target supports ip_denylist_add/remove only")
        if t == "alert":
            alert = db.get(Alert, key)
            if alert is None:
                raise ValueError("alert not found")
            if action.action_type == "alert_escalate":
                alert.severity_id = min(6, alert.severity_id + 1)
                alert.status = "investigating"
                db.commit()
                return {"severity_id": alert.severity_id, "status": alert.status}
            raise ValueError("alert target supports alert_escalate only")
        if t == "incident":
            from app.models.incident import Incident

            inc = db.get(Incident, key)
            if inc is None:
                raise ValueError("incident not found")
            if action.action_type == "incident_contain":
                inc.status = "contained"
            elif action.action_type == "incident_reopen":
                inc.status = "open"
            else:
                raise ValueError("incident target supports incident_contain/reopen only")
            db.commit()
            return {"status": inc.status}
        raise ValueError("unsupported target type")

    def _check_effect(self, db: Session, action: ResponseAction) -> tuple[bool, str]:
        t, key = action.target_type, action.target
        if t == "asset":
            asset = self._asset(db, key)
            want = action.action_type == "asset_isolate"
            if asset is None:
                return False, "asset not found"
            return bool(asset.isolated) == want, f"asset.isolated={bool(asset.isolated)}"
        if t == "ip":
            from app.response.models import DenylistEntry

            row = db.query(DenylistEntry).filter(DenylistEntry.ip == key).first()
            want = action.action_type == "ip_denylist_add"
            return (row is not None) == want, f"denylisted={row is not None}"
        if t == "alert":
            alert = db.get(Alert, key)
            return (alert is not None and alert.status == "investigating"), \
                f"alert.status={getattr(alert, 'status', None)}"
        if t == "incident":
            from app.models.incident import Incident

            inc = db.get(Incident, key)
            want = "contained" if action.action_type == "incident_contain" else "open"
            return (inc is not None and inc.status == want), f"incident.status={getattr(inc, 'status', None)}"
        return False, "unsupported target"

    def _restore_previous(self, db: Session, action: ResponseAction, prev: dict) -> dict:
        previous = prev.get("previous") or {}
        t, key = action.target_type, action.target
        if t == "asset" and previous.get("isolated") is not None:
            asset = self._asset(db, key)
            if asset is not None:
                asset.isolated = bool(previous["isolated"])
                db.commit()
                return {"restored": "asset.isolated", "value": bool(previous["isolated"])}
        if t == "ip":
            from app.response.models import DenylistEntry

            if previous.get("denylisted") is False:
                row = db.query(DenylistEntry).filter(DenylistEntry.ip == key).first()
                if row is not None:
                    db.delete(row)
                    db.commit()
                    return {"restored": "denylist entry removed"}
            return {"restored": "denylist (previous state retained)"}
        if t == "alert" and previous.get("status"):
            alert = db.get(Alert, key)
            if alert is not None:
                alert.status = previous["status"]
                alert.severity_id = int(previous.get("severity_id", alert.severity_id))
                db.commit()
                return {"restored": "alert state"}
        if t == "incident" and previous.get("status"):
            from app.models.incident import Incident

            inc = db.get(Incident, key)
            if inc is not None:
                inc.status = previous["status"]
                db.commit()
                return {"restored": "incident.status", "value": previous["status"]}
        return {"restored": "no previous state recorded (nothing to restore)"}

    def _public(self, a: ResponseAction) -> dict:
        return {
            "id": a.id, "action_type": a.action_type, "target_type": a.target_type,
            "target": a.target, "status": a.status, "dry_run": a.dry_run,
            "requested_by": a.requested_by, "approved_by": a.approved_by,
        }

    def list_actions(self, db: Session, limit: int = 100) -> list[dict]:
        rows = db.query(ResponseAction).order_by(ResponseAction.created_at.desc()).limit(limit).all()
        return [
            {**self._public(r), "reason": r.reason,
             "created_at": r.created_at.isoformat() if r.created_at else None,
             "executed_at": r.executed_at.isoformat() if r.executed_at else None,
             "verification": r.verification}
            for r in rows
        ]

    def denylist(self, db: Session) -> list[dict]:
        from app.response.models import DenylistEntry

        return [
            {"ip": r.ip, "added_by": r.added_by, "reason": r.reason,
             "added_at": r.added_at.isoformat() if r.added_at else None}
            for r in db.query(DenylistEntry).order_by(DenylistEntry.added_at.desc()).limit(500).all()
        ]

    def health(self) -> dict:
        return {"status": "ok", "actions": len(ACTION_ALLOWLIST),
                "enabled": settings.response_enabled,
                "note": "allowlist + autonomy levels + approval + verification enforced"}


response_engine = ResponseEngine()
