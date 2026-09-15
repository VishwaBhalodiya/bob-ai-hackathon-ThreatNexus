"""Asset inventory — the criticality context every alert is scored against."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from database import get_db
from models import Asset
from schemas import AssetCreate, AssetResponse

router = APIRouter(prefix="/api/assets", tags=["assets"])

_CRIT_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@router.get("", response_model=List[AssetResponse])
def list_assets(db: Session = Depends(get_db)):
    rows = db.query(Asset).all()
    return sorted(rows, key=lambda a: (_CRIT_ORDER.get(a.criticality, 9), a.hostname))


@router.post("", response_model=AssetResponse, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    if payload.criticality.upper() not in _CRIT_ORDER:
        raise HTTPException(422, f"criticality must be one of {sorted(_CRIT_ORDER)}")
    if db.query(Asset).filter(Asset.hostname == payload.hostname).first():
        raise HTTPException(409, f"Asset '{payload.hostname}' already exists")
    asset = Asset(**{**payload.model_dump(), "criticality": payload.criticality.upper()})
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
