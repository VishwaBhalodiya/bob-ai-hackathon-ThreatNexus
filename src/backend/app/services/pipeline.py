"""
Alert processing pipeline — ties all services together.

Called when a new alert is ingested:
  1. Extract IOCs from title + description + raw_log
  2. Look up IOC reputations from threat intel DB
  3. Resolve asset and get criticality
  4. Calculate risk score + components
  5. Run AI explanation
  6. Correlate with existing alerts
  7. Persist and return the enriched alert
"""

from typing import Optional
from sqlalchemy.orm import Session

from app.models import Alert, Asset, ThreatIntel
from app.schemas import AlertIngest
from app.services.ioc_extractor import extract_iocs
from app.services.risk_scorer import calculate_risk_score, score_to_level, score_components
from app.services.alert_correlator import correlate_new_alert
from app.services.ai_explainer import generate_explanation


def process_alert(payload: AlertIngest, db: Session) -> Alert:
    """Full enrichment pipeline for a new ingest payload."""

    # ── 1. Create base ORM object ──────────────────────────────────────────────
    alert = Alert(
        title=payload.title,
        description=payload.description,
        source_system=payload.source_system,
        source_severity=payload.source_severity or "medium",
        raw_log=payload.raw_log,
    )

    # ── 2. Resolve asset ───────────────────────────────────────────────────────
    asset: Optional[Asset] = None
    if payload.asset_hostname:
        asset = db.query(Asset).filter(Asset.hostname == payload.asset_hostname).first()
        if asset:
            alert.asset_id = asset.id

    asset_criticality = asset.criticality if asset else 5
    asset_hostname = asset.hostname if asset else "unknown"

    # ── 3. Extract IOCs ────────────────────────────────────────────────────────
    combined_text = " ".join(filter(None, [payload.title, payload.description, payload.raw_log]))
    iocs = extract_iocs(combined_text)
    alert.iocs = iocs

    # ── 4. Threat-intel reputation lookup ──────────────────────────────────────
    ioc_reputations: list[float] = []
    threat_categories: list[str] = []

    for ioc in iocs:
        record: Optional[ThreatIntel] = (
            db.query(ThreatIntel)
            .filter(
                ThreatIntel.ioc_type == ioc["type"],
                ThreatIntel.ioc_value == ioc["value"],
            )
            .first()
        )
        if record:
            ioc_reputations.append(record.reputation_score)
            if record.threat_category:
                threat_categories.append(record.threat_category)

    # ── 5. Risk scoring ────────────────────────────────────────────────────────
    # Correlation check needs existing data so run it after initial flush
    db.add(alert)
    db.flush()  # gives alert.id without committing

    group_id = correlate_new_alert(alert, db)
    alert.correlation_group_id = group_id
    is_correlated = group_id is not None

    components = score_components(
        source_severity=alert.source_severity,
        ioc_reputations=ioc_reputations,
        asset_criticality=asset_criticality,
        threat_categories=threat_categories,
        is_correlated=is_correlated,
    )

    alert.risk_score = components["total"]
    alert.risk_level = components["level"]

    # ── 6. AI explanation ──────────────────────────────────────────────────────
    explanation, steps = generate_explanation(
        title=alert.title,
        description=alert.description or "",
        iocs=iocs,
        risk_score=alert.risk_score,
        risk_level=alert.risk_level,
        asset_hostname=asset_hostname,
        asset_criticality=asset_criticality,
        threat_categories=threat_categories,
        score_components=components,
    )

    alert.ai_explanation = explanation
    alert.investigation_steps = steps

    db.commit()
    db.refresh(alert)
    return alert
