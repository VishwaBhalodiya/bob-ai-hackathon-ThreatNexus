"""Routes for Asset management."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Asset
from app.schemas import AssetCreate, AssetOut

router = APIRouter()


@router.get("/", response_model=List[AssetOut])
def list_assets(db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.criticality.desc()).all()


@router.post("/", response_model=AssetOut, status_code=201)
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    asset = Asset(**payload.model_dump())
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset
