"""
Alert correlation engine.

Groups related alerts into "attack stories" by looking for shared IOCs,
same asset, and temporal proximity. Assigns a shared correlation_group_id
to each group so the frontend can render attack timelines.
"""

import hashlib
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models import Alert


# Maximum time window to consider two alerts as potentially related
CORRELATION_WINDOW_HOURS = 4


def _group_key(ioc_values: List[str], asset_id: Optional[int]) -> str:
    """Produce a stable hash-based group key from IOC values and asset."""
    parts = sorted(ioc_values) + [str(asset_id or "")]
    digest = hashlib.md5("|".join(parts).encode()).hexdigest()[:12]
    return f"grp-{digest}"


def correlate_new_alert(new_alert: Alert, db: Session) -> Optional[str]:
    """
    Attempt to correlate *new_alert* with existing recent alerts.

    Returns the correlation_group_id to assign (existing or newly created),
    or None if no correlation is found.
    """
    if not new_alert.iocs:
        return None

    new_ioc_values = {ioc["value"].lower() for ioc in new_alert.iocs}
    window_start = datetime.utcnow() - timedelta(hours=CORRELATION_WINDOW_HOURS)

    # Candidate alerts: same asset or overlapping time window, not false positives
    candidates: List[Alert] = (
        db.query(Alert)
        .filter(
            Alert.id != new_alert.id,
            Alert.timestamp >= window_start,
            Alert.is_false_positive == False,  # noqa: E712
        )
        .all()
    )

    for candidate in candidates:
        if not candidate.iocs:
            continue

        candidate_ioc_values = {ioc["value"].lower() for ioc in candidate.iocs}
        shared = new_ioc_values & candidate_ioc_values

        # Correlate if: shared IOC exists OR same asset within window
        if shared or (new_alert.asset_id and new_alert.asset_id == candidate.asset_id):
            # Re-use the candidate's existing group if it has one
            if candidate.correlation_group_id:
                return candidate.correlation_group_id
            else:
                # Create a new group and tag the candidate too
                group_id = _group_key(list(new_ioc_values), new_alert.asset_id)
                candidate.correlation_group_id = group_id
                db.add(candidate)
                return group_id

    return None


def get_correlation_summary(db: Session) -> List[dict]:
    """
    Return a list of correlation groups with alert counts and risk summaries.
    Used by the dashboard timeline view.
    """
    groups: dict = {}
    alerts = (
        db.query(Alert)
        .filter(Alert.correlation_group_id != None)  # noqa: E711
        .order_by(Alert.timestamp.asc())
        .all()
    )

    for alert in alerts:
        gid = alert.correlation_group_id
        if gid not in groups:
            groups[gid] = {
                "group_id": gid,
                "alert_count": 0,
                "max_risk_score": 0.0,
                "max_risk_level": "LOW",
                "first_seen": alert.timestamp,
                "last_seen": alert.timestamp,
                "asset_ids": set(),
                "alert_ids": [],
            }

        g = groups[gid]
        g["alert_count"] += 1
        g["max_risk_score"] = max(g["max_risk_score"], alert.risk_score)
        g["max_risk_level"] = alert.risk_level if alert.risk_score >= g["max_risk_score"] else g["max_risk_level"]
        g["first_seen"] = min(g["first_seen"], alert.timestamp)
        g["last_seen"] = max(g["last_seen"], alert.timestamp)
        if alert.asset_id:
            g["asset_ids"].add(alert.asset_id)
        g["alert_ids"].append(alert.id)

    # Serialise sets/datetimes for JSON
    result = []
    for g in groups.values():
        g["asset_ids"] = list(g["asset_ids"])
        g["first_seen"] = g["first_seen"].isoformat()
        g["last_seen"] = g["last_seen"].isoformat()
        result.append(g)

    return sorted(result, key=lambda x: x["max_risk_score"], reverse=True)
