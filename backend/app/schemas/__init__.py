"""Pydantic schemas — strict validation at every trust boundary."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings


class ORMModel(BaseModel):
    """All response models validate directly from SQLAlchemy ORM instances."""
    model_config = ConfigDict(from_attributes=True)


# ------------------------------------------------------------------ auth
class LoginRequest(ORMModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(ORMModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=10, max_length=128)

    @field_validator("new_password")
    @classmethod
    def _policy(cls, v: str) -> str:
        from app.core.security import validate_password_policy

        return validate_password_policy(v)


class UserCreate(ORMModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=10, max_length=128)
    role: Literal["viewer", "analyst", "admin"] = "viewer"
    display_name: str = ""

    @field_validator("password")
    @classmethod
    def _policy(cls, v: str) -> str:
        from app.core.security import validate_password_policy

        return validate_password_policy(v)


class UserOut(ORMModel):
    id: int
    username: str
    display_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


class TokenOut(ORMModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: str
    expires_in: int


# ------------------------------------------------------------------ assets
class AssetCreate(ORMModel):
    hostname: str = Field(min_length=1, max_length=255)
    display_name: str = ""
    asset_type: str = "unknown"
    ip_address: Optional[str] = None
    os: str = ""
    owner: str = ""
    criticality: int = Field(default=3, ge=1, le=5)
    tags: list[str] = Field(default_factory=list)


class AssetOut(ORMModel):
    id: int
    hostname: str
    display_name: str
    asset_type: str
    ip_address: Optional[str]
    os: str
    owner: str
    criticality: int
    auto_registered: bool
    sample: bool
    tags: list[str]
    last_seen: Optional[datetime]
    created_at: datetime


# ------------------------------------------------------------------ events
class RawEvent(ORMModel):
    type: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)
    time: Optional[str] = None


class IngestRequest(ORMModel):
    source: dict[str, Any] = Field(default_factory=dict)
    events: list[RawEvent] = Field(min_length=1, max_length=settings.max_batch_events)


class EventOut(ORMModel):
    id: str
    time: datetime
    class_name: str
    class_uid: str
    severity_id: int
    message: str
    host: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    user: Optional[str]
    action: Optional[str]
    source_product: str
    observables: list[dict]
# ------------------------------------------------------------------ alerts
class AlertPatch(ORMModel):
    status: Literal["new", "ack", "investigating", "resolved", "closed", "false_positive"]
    note: str = ""


class AlertOut(ORMModel):
    id: str
    time: datetime
    rule_id: str
    rule_title: str
    category: str
    severity_id: int
    entity_key: str
    entity_type: str
    attack_ids: list[str]
    attack_tactics: list[str]
    evidence_event_ids: list[str]
    status: str
    message: str
    source_product: str
    incident_id: Optional[str]


# ------------------------------------------------------------------ incidents
class IncidentPatch(ORMModel):
    status: Optional[Literal["open", "investigating", "contained", "resolved", "closed"]] = None
    analyst_notes: Optional[str] = None


class IncidentOut(ORMModel):
    id: str
    title: str
    summary: str
    category: str
    severity_id: int
    entity_keys: list[str]
    attack_ids: list[str]
    attack_chain: bool
    alert_ids: list[str]
    timeline: list[dict]
    status: str
    analyst_notes: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class IncidentDetailOut(IncidentOut):
    alerts: list[AlertOut] = Field(default_factory=list)

