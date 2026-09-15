"""
Risk scoring engine for ThreatNexus.

Combines multiple weighted signals into a final risk score (0–100)
and maps it to a human-readable severity level.
"""

from typing import List, Dict, Any

# ─── Weight constants ──────────────────────────────────────────────────────────

W_SOURCE_SEVERITY = 0.20   # original alert severity from source system
W_IOC_REPUTATION = 0.35    # max IOC reputation score from threat intel
W_ASSET_CRITICALITY = 0.25 # criticality of the targeted asset
W_BEHAVIOUR = 0.10         # behavioural / contextual suspicion bonus
W_CORRELATION = 0.10       # bonus for being part of a correlated attack group


# Source severity → 0-100 normalisation
_SOURCE_MAP = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "unknown": 30,
}

# Threat category → behavioural suspicion bonus (0-100)
_CATEGORY_BONUS = {
    "ransomware": 100,
    "apt": 95,
    "c2": 90,
    "lateral_movement": 85,
    "data_exfiltration": 85,
    "exploit": 80,
    "malware": 75,
    "phishing": 65,
    "botnet": 60,
    "scanner": 30,
    "spam": 20,
}


def calculate_risk_score(
    source_severity: str,
    ioc_reputations: List[float],
    asset_criticality: int,
    threat_categories: List[str],
    is_correlated: bool,
) -> float:
    """
    Compute a weighted risk score in the range [0, 100].

    Parameters
    ----------
    source_severity    : raw severity string from the originating system
    ioc_reputations    : list of reputation scores (0-100) for matched IOCs
    asset_criticality  : 1-10 value from the Asset record
    threat_categories  : list of threat categories from matched threat intel
    is_correlated      : True if this alert belongs to a multi-event group
    """
    # 1. Source severity contribution
    sev_score = _SOURCE_MAP.get(source_severity.lower() if source_severity else "unknown", 30)

    # 2. IOC reputation — take the highest single IOC reputation
    ioc_score = max(ioc_reputations) if ioc_reputations else 0.0

    # 3. Asset criticality — scale 1-10 → 0-100
    asset_score = (asset_criticality / 10) * 100

    # 4. Behavioural bonus — highest matching category
    behaviour_score = 0.0
    for cat in threat_categories:
        behaviour_score = max(behaviour_score, _CATEGORY_BONUS.get(cat.lower(), 0))

    # 5. Correlation bonus — flat bonus if part of correlated group
    correlation_score = 80.0 if is_correlated else 0.0

    # Weighted sum
    score = (
        W_SOURCE_SEVERITY * sev_score
        + W_IOC_REPUTATION * ioc_score
        + W_ASSET_CRITICALITY * asset_score
        + W_BEHAVIOUR * behaviour_score
        + W_CORRELATION * correlation_score
    )

    return min(round(score, 2), 100.0)


def score_to_level(score: float) -> str:
    """Map a numeric risk score to a named severity level."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    else:
        return "LOW"


def score_components(
    source_severity: str,
    ioc_reputations: List[float],
    asset_criticality: int,
    threat_categories: List[str],
    is_correlated: bool,
) -> Dict[str, Any]:
    """Return a breakdown of score components (used for explainability)."""
    sev_score = _SOURCE_MAP.get(source_severity.lower() if source_severity else "unknown", 30)
    ioc_score = max(ioc_reputations) if ioc_reputations else 0.0
    asset_score = (asset_criticality / 10) * 100
    behaviour_score = max(
        (_CATEGORY_BONUS.get(c.lower(), 0) for c in threat_categories), default=0
    )
    correlation_score = 80.0 if is_correlated else 0.0
    total = calculate_risk_score(
        source_severity, ioc_reputations, asset_criticality, threat_categories, is_correlated
    )
    return {
        "total": total,
        "level": score_to_level(total),
        "components": {
            "source_severity": round(W_SOURCE_SEVERITY * sev_score, 2),
            "ioc_reputation": round(W_IOC_REPUTATION * ioc_score, 2),
            "asset_criticality": round(W_ASSET_CRITICALITY * asset_score, 2),
            "behaviour": round(W_BEHAVIOUR * behaviour_score, 2),
            "correlation": round(W_CORRELATION * correlation_score, 2),
        },
    }
