"""Asset inventory API."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import audit
from app.core.database import get_db
from app.core.security import AnalystUser, CurrentUser
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.event import Event
from app.schemas import AssetCreate, AssetOut

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=dict)
def list_assets(
    user: CurrentUser,
    db: Session = Depends(get_db),
    limit: int = Query(500, ge=1, le=2000),
    auto_only: bool = False,
    sample: bool | None = None,
):
    stmt = select(Asset).order_by(Asset.criticality.desc(), Asset.hostname)
    if auto_only:
        stmt = stmt.where(Asset.auto_registered.is_(True))
    if sample is not None:
        stmt = stmt.where(Asset.sample.is_(sample))
    total = db.query(Asset).count()
    rows = db.execute(stmt.limit(limit)).scalars().all()
    return {"total": total, "assets": [AssetOut.model_validate(a).model_dump() for a in rows]}


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, user: AnalystUser, db: Session = Depends(get_db)):
    if db.query(Asset).filter(Asset.hostname == payload.hostname).first():
        from fastapi import HTTPException

        raise HTTPException(409, "asset already exists")
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit.record("asset.create", actor=user.username, details={"hostname": asset.hostname})
    return asset


@router.get("/{asset_id}")
def asset_detail(asset_id: int, user: CurrentUser, db: Session = Depends(get_db)):
    from fastapi import HTTPException
    from sqlalchemy import func

    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, "asset not found")
    event_count = (
        db.query(func.count(Event.id)).filter(Event.host == asset.hostname).scalar() or 0
    )
    alerts_count = (
        db.query(func.count()).select_from(Alert).where(Alert.entity_key == asset.hostname).scalar() or 0
    )
    return {
        "asset": AssetOut.model_validate(asset).model_dump(),
        "event_count": event_count,
        "alert_count": alerts_count,
    }