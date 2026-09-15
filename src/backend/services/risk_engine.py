# Risk scoring engine for ThreatNexus
# Formula (normalized 0-100):
#   risk_score = 0.25*threat_severity + 0.25*ioc_reputation
#              + 0.20*asset_criticality + 0.15*behavioral_suspicion
#              + 0.15*correlation_score

from typing import Optional

# Maps for converting categorical labels to 0-100 numeric values
SEVERITY_MAP = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}

CRITICALITY_MAP = {
    "LOW": 20,
    "MEDIUM": 50,
    "HIGH": 80,
    "CRITICAL": 100,
}

# Behavioral suspicion scores per event type (0-100)
BEHAVIORAL_SUSPICION_MAP = {
    "Port Scan": 60,
    "Brute Force": 75,
    "SQL Injection": 85,
    "Malware Execution": 95,
    "Data Exfiltration": 90,
    "Ransomware": 100,
    "Phishing": 70,
    "Lateral Movement": 85,
    "Privilege Escalation": 90,
    "Command & Control": 95,
    "Credential Dumping": 88,
    "Suspicious Login": 55,
    "DDoS": 65,
    "Unknown": 40,
}


def score_to_priority(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"


def calculate_risk(
    severity: str,
    ioc_reputation: float = 0.0,       # 0-100, from IOC table
    asset_criticality: str = "LOW",
    event_type: str = "Unknown",
    correlation_score: float = 0.0,    # 0-100, from correlation engine
) -> dict:
    """
    Returns a dict with the full risk breakdown and final score/priority.
    """
    threat_severity = SEVERITY_MAP.get(severity.upper(), 20)
    asset_crit = CRITICALITY_MAP.get(asset_criticality.upper(), 20)
    behavioral = BEHAVIORAL_SUSPICION_MAP.get(event_type, 40)

    raw_score = (
        0.25 * threat_severity
        + 0.25 * ioc_reputation
        + 0.20 * asset_crit
        + 0.15 * behavioral
        + 0.15 * correlation_score
    )

    # Clamp to [0, 100]
    risk_score = round(min(max(raw_score, 0.0), 100.0), 2)
    priority = score_to_priority(risk_score)

    return {
        "risk_score": risk_score,
        "priority": priority,
        "breakdown": {
            "threat_severity_input": severity,
            "threat_severity_score": threat_severity,
            "ioc_reputation": ioc_reputation,
            "asset_criticality_input": asset_criticality,
            "asset_criticality_score": asset_crit,
            "behavioral_suspicion": behavioral,
            "correlation_score": correlation_score,
            "weights": {
                "threat_severity": 0.25,
                "ioc_reputation": 0.25,
                "asset_criticality": 0.20,
                "behavioral_suspicion": 0.15,
                "correlation_score": 0.15,
            },
        },
    }
