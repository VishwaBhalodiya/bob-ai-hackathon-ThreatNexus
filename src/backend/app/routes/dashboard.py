"""Dashboard summary endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Alert, ThreatIntel
from app.schemas import DashboardStats, RiskDistribution
from app.services.alert_correlator import get_correlation_summary

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    active = db.query(Alert).filter(Alert.is_false_positive == False)  # noqa: E712

    total = active.count()
    unacked = active.filter(Alert.is_acknowledged == False).count()  # noqa: E712

    dist = RiskDistribution(
        critical=active.filter(Alert.risk_level == "CRITICAL").count(),
        high=active.filter(Alert.risk_level == "HIGH").count(),
        medium=active.filter(Alert.risk_level == "MEDIUM").count(),
        low=active.filter(Alert.risk_level == "LOW").count(),
    )

    top_threats = (
        db.query(ThreatIntel)
        .order_by(ThreatIntel.reputation_score.desc())
        .limit(5)
        .all()
    )

    recent_critical = (
        active.filter(Alert.risk_level == "CRITICAL")
        .order_by(Alert.timestamp.desc())
        .limit(5)
        .all()
    )

    groups = get_correlation_summary(db)

    return DashboardStats(
        total_alerts=total,
        unacknowledged=unacked,
        risk_distribution=dist,
        top_threats=top_threats,
        recent_critical=recent_critical,
        correlation_groups=len(groups),
    )


@router.get("/correlations")
def get_correlations(db: Session = Depends(get_db)):
    return get_correlation_summary(db)
