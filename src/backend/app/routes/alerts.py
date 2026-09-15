"""Routes for Alert ingestion and retrieval."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertIngest, AlertOut
from app.services.pipeline import process_alert

router = APIRouter()


@router.post("/ingest", response_model=AlertOut, status_code=201)
def ingest_alert(payload: AlertIngest, db: Session = Depends(get_db)):
    """
    Ingest a new security alert.
    The pipeline will extract IOCs, score risk, correlate, and generate an AI explanation.
    """
    alert = process_alert(payload, db)
    return alert


@router.get("/", response_model=List[AlertOut])
def list_alerts(
    risk_level: Optional[str] = Query(None, description="Filter by risk level: LOW/MEDIUM/HIGH/CRITICAL"),
    source_system: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db),
):
    """List alerts, sorted by risk score descending (highest priority first)."""
    q = db.query(Alert)
    if risk_level:
        q = q.filter(Alert.risk_level == risk_level.upper())
    if source_system:
        q = q.filter(Alert.source_system == source_system)
    if acknowledged is not None:
        q = q.filter(Alert.is_acknowledged == acknowledged)
    q = q.filter(Alert.is_false_positive == False)  # noqa: E712
    q = q.order_by(Alert.risk_score.desc(), Alert.timestamp.desc())
    return q.offset(offset).limit(limit).all()


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_acknowledged = True
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("/{alert_id}/false-positive", response_model=AlertOut)
def mark_false_positive(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_false_positive = True
    alert.risk_level = "FALSE_POSITIVE"
    db.commit()
    db.refresh(alert)
    return alert
