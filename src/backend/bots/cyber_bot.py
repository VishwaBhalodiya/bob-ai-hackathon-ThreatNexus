# Bot 1 — Cyber/SIEM Bot
#
# Handles all cyber-domain data sources:
#   - SIEM alerts (JSON, key=value, syslog)
#   - EDR / endpoint sensor detections
#   - Network sensor / IDS events
#   - Firewall logs
#   - Authentication logs
#
# For each event the bot:
#   1. Normalises it to a canonical CyberEvent struct
#   2. Extracts all IOCs (IPs, domains, URLs, hashes)
#   3. Assigns a cyber confidence score (0-100)
#   4. Proposes a MITRE ATT&CK technique candidate
#
# The output of this bot feeds directly into Bot 4 (Fusion Bot).

import re
from datetime import datetime
from typing import Optional

from services.mitre_mapper import normalise_event_type, map_event
from services.ioc_extractor import extract_iocs
from services.risk_engine import SEVERITY_MAP

# ── Canonical event severity normalisation ────────────────────────────────────

_SEV_ALIASES = {
    "critical": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH", "warning": "HIGH",
    "medium": "MEDIUM", "moderate": "MEDIUM", "med": "MEDIUM",
    "low": "LOW", "info": "LOW", "informational": "LOW",
}

# Behavioral confidence scores per event type (how certain is it that this
# event type, if correctly identified, represents adversary activity)
_BEHAVIOR_CONFIDENCE: dict[str, float] = {
    "Ransomware":           0.95,
    "Malware Execution":    0.90,
    "Command & Control":    0.90,
    "Data Exfiltration":    0.88,
    "Credential Dumping":   0.88,
    "Privilege Escalation": 0.82,
    "Lateral Movement":     0.80,
    "SQL Injection":        0.80,
    "Web Shell":            0.78,
    "DNS Tunneling":        0.75,
    "Brute Force":          0.70,
    "Phishing":             0.68,
    "Persistence":          0.65,
    "Suspicious Login":     0.55,
    "Port Scan":            0.45,
    "Reconnaissance":       0.45,
    "DDoS":                 0.50,
    "Unknown":              0.30,
}


def _normalise_severity(raw: Optional[str]) -> str:
    if not raw:
        return "MEDIUM"
    return _SEV_ALIASES.get(raw.strip().lower(), "MEDIUM")


def _cyber_confidence(event_type: str, severity: str, ioc_count: int) -> float:
    """
    Estimate how confident we are that this raw cyber event represents real
    adversary activity (0.0-1.0).

    Combines:
    - Behavioral confidence of the event type
    - Severity weight
    - IOC presence boost (if the event carries indicators, it is more credible)
    """
    behavior = _BEHAVIOR_CONFIDENCE.get(event_type, 0.30)
    sev_weight = SEVERITY_MAP.get(severity, 50) / 100.0
    ioc_boost = min(ioc_count * 0.05, 0.15)
    raw = behavior * 0.6 + sev_weight * 0.25 + ioc_boost
    return round(min(max(raw, 0.0), 1.0), 3)


# ── Public API ─────────────────────────────────────────────────────────────────

def process_event(raw_event: dict) -> dict:
    """
    Accept a raw cyber event (from SIEM, EDR, network sensor, firewall, etc.)
    and return a normalised CyberEvent dict.

    Input fields (all optional — sensible defaults apply):
        source, timestamp, src_ip, dst_ip, host, user, event,
        event_code, severity, process, commandline, bytes_out

    Output shape:
        {
            "bot":              "CYBER_BOT",
            "event_id":         str,               # CYB-<timestamp-hash>
            "source":           str,               # SIEM | EDR | NETWORK_SENSOR | FIREWALL | IDS
            "timestamp":        datetime,
            "src_ip":           str,
            "dst_ip":           str | None,
            "entity":           str,               # hostname / asset identifier
            "user":             str | None,
            "behavior":         str,               # raw event description
            "event_type":       str,               # canonical type (normalised)
            "severity":         str,               # LOW | MEDIUM | HIGH | CRITICAL
            "iocs":             list[dict],        # extracted IOCs
            "mitre_candidate":  dict | None,       # {technique_id, technique, tactic, url}
            "cyber_confidence": float,             # 0.0-1.0
            "raw":              dict,              # original input
        }
    """
    src_ip     = raw_event.get("src_ip") or raw_event.get("source_ip") or "0.0.0.0"
    dst_ip     = raw_event.get("dst_ip") or raw_event.get("destination_ip")
    entity     = raw_event.get("host") or raw_event.get("hostname") or dst_ip or "unknown"
    user       = raw_event.get("user") or raw_event.get("username")
    behavior   = (
        raw_event.get("event") or raw_event.get("message")
        or raw_event.get("description") or raw_event.get("event_type") or "Unknown event"
    )
    severity   = _normalise_severity(raw_event.get("severity"))
    source     = (raw_event.get("source") or raw_event.get("log_source") or "CYBER_SENSOR").upper()

    ts_raw = raw_event.get("timestamp") or raw_event.get("@timestamp")
    if isinstance(ts_raw, datetime):
        ts = ts_raw
    elif ts_raw:
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    # Normalise the free-text event description to a canonical event type
    event_type = normalise_event_type(behavior)

    # Extract all IOCs from the full text blob (behavior + commandline + raw fields)
    text_blob = " ".join(str(v) for v in raw_event.values() if isinstance(v, str))
    iocs = extract_iocs(text_blob)

    mitre = map_event(event_type)
    confidence = _cyber_confidence(event_type, severity, len(iocs))

    # Build a deterministic event ID from source + timestamp + src_ip
    ts_str = ts.strftime("%Y%m%d%H%M%S")
    event_id = f"CYB-{ts_str}-{abs(hash(src_ip + behavior)) % 100000:05d}"

    return {
        "bot":              "CYBER_BOT",
        "event_id":         event_id,
        "source":           source,
        "timestamp":        ts,
        "src_ip":           src_ip,
        "dst_ip":           dst_ip,
        "entity":           entity,
        "user":             user,
        "behavior":         behavior,
        "event_type":       event_type,
        "severity":         severity,
        "iocs":             iocs,
        "mitre_candidate":  mitre,
        "cyber_confidence": confidence,
        "raw":              raw_event,
    }


def process_batch(events: list[dict]) -> list[dict]:
    """Process a list of raw cyber events and return normalised CyberEvent dicts."""
    return [process_event(e) for e in events]
