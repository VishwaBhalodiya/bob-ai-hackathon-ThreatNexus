# Correlation engine – groups alerts by shared source_ip or asset_id
# within a configurable time window and flags potential attack chains.

from sqlalchemy.orm import Session
from models import Alert
from datetime import datetime, timedelta
from typing import List, Optional

# How far back to look for the existing score/chain helpers
DEFAULT_WINDOW_HOURS = 24

# Narrow window used by get_related_events() for the alert-detail view.
# Configurable via the window_minutes parameter; this is just the default.
DEFAULT_RELATED_WINDOW_MINUTES = 10

# MITRE tactic lookup lives in mitre_mapper (single source of truth).
from services.mitre_mapper import tactic_for as _tactic_for


def get_correlated_alerts(
    db: Session,
    source_ip: str,
    asset_id: int | None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> List[Alert]:
    """
    Return all OPEN alerts that share the same source_ip OR asset_id
    and fall within the last `window_hours`.
    """
    since = datetime.utcnow() - timedelta(hours=window_hours)

    query = db.query(Alert).filter(Alert.timestamp >= since)

    if asset_id is not None:
        query = query.filter(
            (Alert.source_ip == source_ip) | (Alert.asset_id == asset_id)
        )
    else:
        query = query.filter(Alert.source_ip == source_ip)

    return query.all()


def calculate_correlation_score(
    db: Session,
    source_ip: str,
    asset_id: int | None,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> float:
    """
    Returns a 0-100 score reflecting how many correlated alerts exist.
    Scale: 0 related alerts -> 0, 10+ alerts -> 100.
    """
    correlated = get_correlated_alerts(db, source_ip, asset_id, window_hours)
    count = len(correlated)
    # Cap at 10 for maximum score
    score = min(count / 10.0, 1.0) * 100.0
    return round(score, 2)


def detect_attack_chains(
    db: Session,
    window_hours: int = DEFAULT_WINDOW_HOURS,
) -> List[dict]:
    """
    Scan all recent alerts and group them by source_ip into candidate attack
    chains.  A chain is flagged multi-stage when its alerts span 3+ distinct
    MITRE tactics AND at least one of them is not a likely false positive —
    a cluster of suppressed noise is never promoted to an attack chain.
    Returns chain summaries sorted by max risk (for the commander brief and
    /api/attack-chains).
    """
    from services.mitre_mapper import TACTIC_ORDER

    since = datetime.utcnow() - timedelta(hours=window_hours)
    recent_alerts = (
        db.query(Alert)
        .filter(Alert.timestamp >= since)
        .order_by(Alert.timestamp)
        .all()
    )

    chains: dict = {}
    for alert in recent_alerts:
        chains.setdefault(alert.source_ip, []).append(alert)

    attack_chains = []
    for ip, alerts in chains.items():
        if len(alerts) < 2:
            continue
        tactics_seen = {_tactic_for(a.event_type) for a in alerts} - {None}
        ordered_tactics = [t for t in TACTIC_ORDER if t in tactics_seen]
        genuine = sum(1 for a in alerts if a.verdict == "GENUINE_THREAT")
        suppressed = sum(1 for a in alerts if a.verdict == "LIKELY_FALSE_POSITIVE")
        multi_stage = len(ordered_tactics) >= 3 and genuine >= 1
        assets = sorted({a.asset_id for a in alerts if a.asset_id is not None})
        max_risk = max(a.risk_score for a in alerts)
        if multi_stage:
            flagged = "Multi-stage Attack Chain"
        elif suppressed == len(alerts):
            flagged = "Suppressed Noise Cluster"
        else:
            flagged = "Correlated Activity Cluster"
        attack_chains.append(
            {
                "source_ip":       ip,
                "alert_count":     len(alerts),
                "alert_ids":       [a.id for a in alerts],
                "asset_ids":       assets,
                "event_types":     [a.event_type for a in alerts],
                "tactics":         ordered_tactics,
                "first_seen":      alerts[0].timestamp,
                "last_seen":       alerts[-1].timestamp,
                "max_risk_score":  max_risk,
                "genuine_count":   genuine,
                "suppressed_count": suppressed,
                "is_multi_stage":  multi_stage,
                "priority":        "CRITICAL" if max_risk >= 80 else "HIGH" if max_risk >= 60 else "MEDIUM" if max_risk >= 30 else "LOW",
                "flagged_as":      flagged,
            }
        )

    return sorted(
        attack_chains,
        key=lambda x: (x["is_multi_stage"], x["max_risk_score"]),
        reverse=True,
    )


def get_related_events_at(
    db: Session,
    timestamp: datetime,
    source_ip: str,
    asset_id: Optional[int],
    exclude_id: Optional[int] = None,
    window_minutes: int = DEFAULT_RELATED_WINDOW_MINUTES,
) -> List[dict]:
    """
    Return alerts sharing the same source_ip OR asset_id within
    `window_minutes` on either side of `timestamp`, ordered ascending.

    Works for alerts that have not been persisted yet (ingest path) — pass
    exclude_id for an existing alert so it is not returned as its own sibling.
    Each item is a plain dict so it serialises cleanly through Pydantic.
    """
    delta = timedelta(minutes=window_minutes)
    window_start = timestamp - delta
    window_end   = timestamp + delta

    query = (
        db.query(Alert)
        .filter(Alert.timestamp >= window_start)
        .filter(Alert.timestamp <= window_end)
    )
    if exclude_id is not None:
        query = query.filter(Alert.id != exclude_id)

    if asset_id is not None:
        query = query.filter(
            (Alert.source_ip == source_ip) | (Alert.asset_id == asset_id)
        )
    else:
        query = query.filter(Alert.source_ip == source_ip)

    rows: List[Alert] = query.order_by(Alert.timestamp).all()

    return [
        {
            "id":           a.id,
            "timestamp":    a.timestamp,
            "source_ip":    a.source_ip,
            "destination_ip": a.destination_ip,
            "event_type":   a.event_type,
            "severity":     a.severity,
            "priority":     a.priority,
            "risk_score":   a.risk_score,
            "status":       a.status,
            "asset_id":     a.asset_id,
            "verdict":      a.verdict,
            "mitre_tactic": _tactic_for(a.event_type),
        }
        for a in rows
    ]


def get_related_events(
    db: Session,
    current_alert_id: int,
    source_ip: str,
    asset_id: Optional[int],
    window_minutes: int = DEFAULT_RELATED_WINDOW_MINUTES,
) -> List[dict]:
    """
    Sibling alerts of an existing alert (see get_related_events_at).
    The current alert itself is excluded from results.
    """
    current: Optional[Alert] = db.query(Alert).filter(Alert.id == current_alert_id).first()
    if not current:
        return []
    return get_related_events_at(
        db, current.timestamp, source_ip, asset_id,
        exclude_id=current_alert_id, window_minutes=window_minutes,
    )


def classify_attack_chain(
    current_event_type: str,
    related_events: List[dict],
) -> bool:
    """
    Return True when the current alert plus its related events collectively
    span 3 or more distinct MITRE tactics AND there are at least 3 events
    total — indicating a multi-stage, coordinated attack chain.
    """
    all_events = [current_event_type] + [e["event_type"] for e in related_events]
    # Need at least 3 events total
    if len(all_events) < 3:
        return False
    tactics = {_tactic_for(et) for et in all_events} - {None}
    return len(tactics) >= 3
