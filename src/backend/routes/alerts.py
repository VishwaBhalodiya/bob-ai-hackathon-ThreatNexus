from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from database import get_db
from models import Alert, ThreatEvent
from schemas import (
    AlertResponse, AlertDetailResponse, RelatedEventResponse, AIExplanation,
    VerdictResponse, MitreResponse, FeedbackRequest, FEEDBACK_VALUES,
    StatusRequest, STATUS_VALUES,
)
from services import threat_intelligence, pipeline
from services.fp_classifier import VERDICT_VALUES
from services.ioc_extractor import extract_iocs

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    verdict: Optional[str] = Query(None, description="GENUINE_THREAT | LIKELY_FALSE_POSITIVE | NEEDS_REVIEW"),
    status: Optional[str] = Query(None),
    source: Optional[str] = Query(None, description="Feed name, e.g. Firewall"),
    db: Session = Depends(get_db),
):
    """Return alerts sorted by risk_score descending, with optional filters."""
    q = db.query(Alert)
    if verdict:
        v = verdict.upper()
        if v not in VERDICT_VALUES:
            raise HTTPException(422, f"verdict must be one of {sorted(VERDICT_VALUES)}")
        q = q.filter(Alert.verdict == v)
    if status:
        q = q.filter(Alert.status == status.upper())
    if source:
        q = q.filter(Alert.source == source)
    return q.order_by(Alert.risk_score.desc()).all()


@router.post("/rescore")
def rescore_alerts(db: Session = Depends(get_db)):
    """
    Re-run enrichment, correlation, risk scoring, MITRE mapping and the
    false-positive verdict over every stored alert and persist the results.
    Use after bulk feedback or a threat-intel update.
    """
    return pipeline.rescore_all(db)


@router.get("/{alert_id}", response_model=AlertDetailResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    """Full alert detail: asset, IOC, correlation, MITRE, verdict, risk breakdown, BLUF."""
    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    res = pipeline.assess_alert(db, alert, with_explanation=True)

    # Keep the stored (list-view) fields in step with the live assessment.
    pipeline.apply_to_alert(alert, res)
    db.commit()

    return AlertDetailResponse(
        id=alert.id,
        timestamp=alert.timestamp,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        event_type=alert.event_type,
        severity=alert.severity,
        asset_id=alert.asset_id,
        status=alert.status,
        risk_score=res["risk"]["risk_score"],
        priority=res["risk"]["priority"],
        feedback=alert.feedback,
        feedback_at=alert.feedback_at,
        source=alert.source or "SIEM",
        raw_log=alert.raw_log,
        description=alert.description,
        feed_format=alert.feed_format,
        verdict=alert.verdict,
        verdict_confidence=alert.verdict_confidence,
        mitre_technique_id=alert.mitre_technique_id,
        mitre_technique=alert.mitre_technique,
        mitre_tactic=alert.mitre_tactic,
        iocs=res["iocs"],
        asset=res["asset"],
        threat_events=alert.threat_events,
        recommendations=alert.recommendations,
        ioc_info=res["ioc"],
        risk_breakdown=res["risk"]["breakdown"],
        ai_explanation=AIExplanation(**res["explanation"]),
        related_events=[RelatedEventResponse(**e) for e in res["related_events"]],
        is_attack_chain=res["is_attack_chain"],
        correlation_count=res["correlation_count"],
        verdict_detail=VerdictResponse(**res["verdict"]),
        mitre=MitreResponse(**res["mitre"]) if res["mitre"] else None,
    )


@router.patch("/{alert_id}/feedback", response_model=AlertResponse)
def set_feedback(
    alert_id: int,
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
):
    """Set analyst triage feedback on an alert."""
    value = payload.feedback.upper()
    if value not in FEEDBACK_VALUES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid feedback value '{value}'. Must be one of: {sorted(FEEDBACK_VALUES)}",
        )

    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert.feedback = value
    alert.feedback_at = datetime.utcnow()

    # Analyst decisions feed straight back into the verdict (and into the
    # history signal used for future alerts from the same source).
    pipeline.apply_to_alert(alert, pipeline.assess_alert(db, alert, with_explanation=False))
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("/{alert_id}/status", response_model=AlertResponse)
def set_status(alert_id: int, payload: StatusRequest, db: Session = Depends(get_db)):
    """Move an alert through the triage workflow: OPEN → IN_PROGRESS → RESOLVED."""
    value = payload.status.upper()
    if value not in STATUS_VALUES:
        raise HTTPException(422, f"status must be one of {sorted(STATUS_VALUES)}")
    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = value
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/{alert_id}/extract-iocs")
def extract_alert_iocs(alert_id: int, db: Session = Depends(get_db)):
    """
    Run regex IOC extraction against the alert's raw_log + description,
    look each extracted IOC up in the threat intelligence table, and
    create ThreatEvent rows for any with reputation >= 40.
    Returns the extracted IOC list annotated with reputation lookups.
    """
    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    text = f"{alert.description or ''} {alert.raw_log or ''}".strip()
    raw_iocs = extract_iocs(text)

    enriched: list[dict] = []
    for ioc in raw_iocs:
        ti = threat_intelligence.lookup_ioc(db, ioc["value"])
        found = ti.get("ioc_id") is not None
        reputation = ti.get("reputation", 0)

        # Create a ThreatEvent if the IOC is known and above noise threshold
        if found and reputation >= 40:
            already = (
                db.query(ThreatEvent)
                .filter(
                    ThreatEvent.alert_id == alert_id,
                    ThreatEvent.ioc_id == ti["ioc_id"],
                )
                .first()
            )
            if not already:
                te = ThreatEvent(
                    alert_id=alert_id,
                    ioc_id=ti["ioc_id"],
                    event_type="IOC Match",
                    description=(
                        f"Extracted {ioc['type']} {ioc['value']} from raw log; "
                        f"reputation {reputation:.0f}/100 ({ti.get('threat_type') or 'unknown'})."
                    ),
                    timestamp=datetime.utcnow(),
                )
                db.add(te)

        enriched.append({
            "type":        ioc["type"],
            "value":       ioc["value"],
            "found":       found,
            "reputation":  reputation,
            "confidence":  ti.get("confidence", 0),
            "threat_type": ti.get("threat_type"),
        })

    db.commit()
    return {"alert_id": alert_id, "iocs": enriched}
