from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Alert
from schemas import (
    DashboardResponse, FeedbackSummary, VerdictSummary,
    AnalyzeRequest, AnalyzeResponse, AIExplanation, IOCResponse,
    VerdictResponse, MitreResponse,
)
from services import ai_engine, correlation_engine, pipeline

router = APIRouter(tags=["dashboard"])


@router.get("/api/dashboard", response_model=DashboardResponse)
def get_dashboard(db: Session = Depends(get_db)):
    """Return counts of total / critical / high / medium / low alerts, feedback summary, and sources breakdown."""
    all_alerts = db.query(Alert).all()
    counts = {"total": len(all_alerts), "critical": 0, "high": 0, "medium": 0, "low": 0}
    feedback_counts = {"UNREVIEWED": 0, "TRUE_POSITIVE": 0, "FALSE_POSITIVE": 0, "ESCALATED": 0}
    verdict_counts = {"GENUINE_THREAT": 0, "LIKELY_FALSE_POSITIVE": 0, "NEEDS_REVIEW": 0}
    sources_breakdown: dict = {}
    formats_breakdown: dict = {}
    tactic_breakdown: dict = {}

    for a in all_alerts:
        p = a.priority.upper()
        if p == "CRITICAL":
            counts["critical"] += 1
        elif p == "HIGH":
            counts["high"] += 1
        elif p == "MEDIUM":
            counts["medium"] += 1
        else:
            counts["low"] += 1

        fb = (a.feedback or "UNREVIEWED").upper()
        if fb in feedback_counts:
            feedback_counts[fb] += 1
        else:
            feedback_counts["UNREVIEWED"] += 1

        src = a.source or "SIEM"
        sources_breakdown[src] = sources_breakdown.get(src, 0) + 1

        v = (a.verdict or "NEEDS_REVIEW").upper()
        verdict_counts[v if v in verdict_counts else "NEEDS_REVIEW"] += 1

        fmt = a.feed_format or "seed"
        formats_breakdown[fmt] = formats_breakdown.get(fmt, 0) + 1

        if a.mitre_tactic:
            tactic_breakdown[a.mitre_tactic] = tactic_breakdown.get(a.mitre_tactic, 0) + 1

    counts["feedback_summary"] = FeedbackSummary(
        unreviewed=feedback_counts["UNREVIEWED"],
        true_positive=feedback_counts["TRUE_POSITIVE"],
        false_positive=feedback_counts["FALSE_POSITIVE"],
        escalated=feedback_counts["ESCALATED"],
    )
    counts["verdict_summary"] = VerdictSummary(
        genuine=verdict_counts["GENUINE_THREAT"],
        likely_false_positive=verdict_counts["LIKELY_FALSE_POSITIVE"],
        needs_review=verdict_counts["NEEDS_REVIEW"],
    )
    counts["sources_breakdown"] = sources_breakdown
    counts["formats_breakdown"] = formats_breakdown
    counts["tactic_breakdown"] = tactic_breakdown
    counts["attack_chains"] = sum(
        1 for c in correlation_engine.detect_attack_chains(db) if c["is_multi_stage"]
    )
    return counts


@router.get("/api/ai/status")
def ai_status():
    """Which engine is producing BLUF text right now: IBM Bob or the template fallback."""
    return ai_engine.status()


@router.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    Accepts {source_ip, event_type, asset_id, severity}, runs the full
    assessment pipeline and returns the result without persisting anything.
    """
    res = pipeline.assess(
        db,
        source_ip=payload.source_ip, event_type=payload.event_type,
        severity=payload.severity or "MEDIUM", asset_id=payload.asset_id,
        raw_text=payload.raw_text, with_explanation=True,
    )
    return AnalyzeResponse(
        risk_score=res["risk"]["risk_score"],
        priority=res["risk"]["priority"],
        confidence=res["ioc_data"]["confidence"],
        recommendation=ai_engine.generate_recommendation(res["alert_data"]),
        ai_explanation=AIExplanation(**res["explanation"]),
        risk_breakdown=res["risk"]["breakdown"],
        ioc_info=IOCResponse.model_validate(res["ioc"]) if res["ioc"] else None,
        verdict=VerdictResponse(**res["verdict"]),
        mitre=MitreResponse(**res["mitre"]) if res["mitre"] else None,
        correlation_count=res["correlation_count"],
        is_attack_chain=res["is_attack_chain"],
        iocs=res["iocs"],
    )
