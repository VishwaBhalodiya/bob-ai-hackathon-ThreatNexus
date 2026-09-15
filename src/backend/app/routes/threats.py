"""Routes for Threat Intelligence records."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatIntel
from app.schemas import ThreatIntelCreate, ThreatIntelOut

router = APIRouter()


@router.get("/", response_model=List[ThreatIntelOut])
def list_threat_intel(
    ioc_type: Optional[str] = Query(None),
    min_reputation: float = Query(0.0, ge=0, le=100),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(ThreatIntel).filter(ThreatIntel.reputation_score >= min_reputation)
    if ioc_type:
        q = q.filter(ThreatIntel.ioc_type == ioc_type)
    return q.order_by(ThreatIntel.reputation_score.desc()).limit(limit).all()


@router.post("/", response_model=ThreatIntelOut, status_code=201)
def add_threat_intel(payload: ThreatIntelCreate, db: Session = Depends(get_db)):
    record = ThreatIntel(**payload.model_dump())
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/lookup/{ioc_value}", response_model=Optional[ThreatIntelOut])
def lookup_ioc(ioc_value: str, db: Session = Depends(get_db)):
    return (
        db.query(ThreatIntel)
        .filter(ThreatIntel.ioc_value == ioc_value)
        .order_by(ThreatIntel.reputation_score.desc())
        .first()
    )
