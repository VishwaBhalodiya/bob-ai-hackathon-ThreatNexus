"""Threat-intelligence indicators (IOCs)."""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db
from models import IOC
from schemas import IOCCreate, IOCResponse
from services import threat_intelligence

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


@router.get("", response_model=List[IOCResponse])
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="IP | DOMAIN | URL | HASH | EMAIL"),
    min_reputation: float = Query(0.0, ge=0, le=100),
    db: Session = Depends(get_db),
):
    q = db.query(IOC).filter(IOC.reputation >= min_reputation)
    if ioc_type:
        q = q.filter(IOC.ioc_type == ioc_type.upper())
    return q.order_by(IOC.reputation.desc()).all()


@router.post("", response_model=IOCResponse, status_code=201)
def add_ioc(payload: IOCCreate, db: Session = Depends(get_db)):
    """Add or strengthen a single indicator (bulk intel arrives via STIX at /api/ingest)."""
    row = db.query(IOC).filter(IOC.ioc_value == payload.ioc_value).first()
    now = datetime.utcnow()
    if row:
        row.reputation  = max(row.reputation or 0, payload.reputation)
        row.confidence  = max(row.confidence or 0, payload.confidence)
        row.threat_type = payload.threat_type or row.threat_type
        row.last_seen   = payload.last_seen or now
    else:
        row = IOC(
            ioc_value=payload.ioc_value, ioc_type=payload.ioc_type.upper(),
            reputation=payload.reputation, confidence=payload.confidence,
            threat_type=payload.threat_type,
            first_seen=payload.first_seen or now, last_seen=payload.last_seen or now,
        )
        db.add(row)
    db.commit()
    db.refresh(row)
    return row


@router.get("/lookup/{ioc_value:path}")
def lookup(ioc_value: str, db: Session = Depends(get_db)):
    """Reputation lookup for any indicator value; unknown values return reputation 0."""
    return threat_intelligence.lookup_ioc(db, ioc_value)
