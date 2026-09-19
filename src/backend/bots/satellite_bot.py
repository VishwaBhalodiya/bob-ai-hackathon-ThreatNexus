# Bot 3 — Satellite/Telemetry Bot
#
# Handles satellite and telemetry data sources:
#   - Satellite telemetry streams
#   - Communication anomaly feeds
#   - Ground-station status
#   - Signal anomalies
#   - Asset timing anomalies
#
# Design note: the satellite bot does NOT say "satellite anomaly = cyber attack".
# Instead it produces an independent evidence stream that the Fusion Bot can
# use to corroborate or contradict observations from the Cyber and Intelligence
# bots.  A satellite communication anomaly coinciding (±15 min) with a cyber
# event on a co-located asset is meaningful context; in isolation it is just
# an anomaly.
#
# For each input the bot:
#   1. Normalises the telemetry record to a canonical SatelliteEvent
#   2. Computes an anomaly severity from the anomaly_score and delta values
#   3. Classifies the anomaly type (communication | timing | signal | state)
#   4. Produces a human-readable evidence description for the Fusion Bot

from datetime import datetime
from typing import Optional

# Anomaly score thresholds → severity
_SCORE_SEVERITY: list[tuple[float, str]] = [
    (0.85, "CRITICAL"),
    (0.65, "HIGH"),
    (0.40, "MEDIUM"),
    (0.0,  "LOW"),
]

# Anomaly type classification from anomaly_type field or event description
_ANOMALY_TYPE_MAP: list[tuple[str, str]] = [
    ("communication",  "communication_degradation"),
    ("timing",         "timing_anomaly"),
    ("signal",         "signal_anomaly"),
    ("state",          "state_change"),
    ("jamm",           "jamming_suspected"),
    ("spoof",          "spoofing_suspected"),
    ("dropout",        "communication_degradation"),
    ("latency",        "communication_degradation"),
    ("degraded",       "communication_degradation"),
]


def _classify_anomaly_type(raw_type: Optional[str], description: str) -> str:
    combined = ((raw_type or "") + " " + description).lower()
    for keyword, atype in _ANOMALY_TYPE_MAP:
        if keyword in combined:
            return atype
    return "general_anomaly"


def _score_to_severity(score: float) -> str:
    for threshold, sev in _SCORE_SEVERITY:
        if score >= threshold:
            return sev
    return "LOW"


def _anomaly_score(raw: dict) -> float:
    """
    Derive an anomaly score from the raw telemetry record.
    Prefers an explicit anomaly_score field; otherwise estimates from
    latency ratios and signal-strength deltas.
    """
    if "anomaly_score" in raw and raw["anomaly_score"] is not None:
        return float(raw["anomaly_score"])

    score = 0.0

    # Latency anomaly
    actual   = raw.get("uplink_latency_ms")
    expected = raw.get("expected_latency_ms")
    if actual and expected and expected > 0:
        ratio = actual / expected
        if ratio > 10:
            score = max(score, 0.90)
        elif ratio > 5:
            score = max(score, 0.75)
        elif ratio > 2:
            score = max(score, 0.55)
        elif ratio > 1.5:
            score = max(score, 0.35)

    # Signal-strength delta
    delta = raw.get("signal_strength_delta")
    if delta is not None:
        delta_abs = abs(float(delta))
        if delta_abs > 0.5:
            score = max(score, 0.85)
        elif delta_abs > 0.3:
            score = max(score, 0.65)
        elif delta_abs > 0.15:
            score = max(score, 0.40)

    # Communication status as a floor
    comm_status = (raw.get("communication_status") or "").lower()
    if comm_status == "failed":
        score = max(score, 0.80)
    elif comm_status in ("degraded", "intermittent"):
        score = max(score, 0.60)
    elif comm_status == "anomalous":
        score = max(score, 0.45)

    return round(score, 3)


def _build_evidence_description(
    asset_id: str,
    anomaly_type: str,
    severity: str,
    score: float,
    raw: dict,
) -> str:
    """
    Produce a human-readable evidence sentence for the Fusion Bot.
    This is the key output that makes the satellite stream interpretable
    in a multi-source context without over-claiming a cyber connection.
    """
    base = f"{asset_id} ({raw.get('source', 'SATELLITE')}) reported a {anomaly_type.replace('_', ' ')} anomaly (score {score:.2f})"
    status = raw.get("communication_status", "")
    latency = raw.get("uplink_latency_ms")
    expected = raw.get("expected_latency_ms")
    delta = raw.get("signal_strength_delta")

    details = []
    if status and status.lower() not in ("normal", ""):
        details.append(f"communication status: {status}")
    if latency and expected:
        details.append(f"latency {latency}ms vs expected {expected}ms")
    if delta is not None:
        details.append(f"signal strength delta: {float(delta):+.0%}")

    description = base
    if details:
        description += f" — {'; '.join(details)}"
    description += (
        f". Independent telemetry evidence; cross-source correlation required "
        f"before attributing to a cyber event."
    )
    return description


# ── Public API ─────────────────────────────────────────────────────────────────

def process_telemetry(raw_event: dict) -> dict:
    """
    Accept a raw satellite/telemetry record and return a normalised
    SatelliteEvent dict.

    Input fields (all optional):
        source, timestamp, asset_id, telemetry_status, communication_status,
        location_zone, anomaly_score, signal_strength_delta,
        uplink_latency_ms, expected_latency_ms, anomaly_type, description

    Output shape:
        {
            "bot":                "SATELLITE_BOT",
            "event_id":           str,           # SAT-<timestamp-hash>
            "source":             str,           # SATELLITE | GROUND_STATION
            "timestamp":          datetime,
            "asset_id":           str,
            "zone":               str | None,
            "anomaly_type":       str,           # communication_degradation | timing_anomaly | …
            "anomaly_score":      float,         # 0.0-1.0
            "severity":           str,           # LOW | MEDIUM | HIGH | CRITICAL
            "evidence_description": str,         # human-readable evidence for Fusion Bot
            "is_anomalous":       bool,
            "raw":                dict,
        }
    """
    source    = (raw_event.get("source") or "SATELLITE").upper()
    asset_id  = str(raw_event.get("asset_id") or "UNKNOWN")
    zone      = raw_event.get("location_zone") or raw_event.get("zone")
    description = raw_event.get("description") or ""

    ts_raw = raw_event.get("timestamp")
    if isinstance(ts_raw, datetime):
        ts = ts_raw
    elif ts_raw:
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    score = _anomaly_score(raw_event)
    severity = _score_to_severity(score)
    anomaly_type = _classify_anomaly_type(
        raw_event.get("anomaly_type"), description
    )
    is_anomalous = score >= 0.35

    evidence = _build_evidence_description(asset_id, anomaly_type, severity, score, raw_event)

    ts_str = ts.strftime("%Y%m%d%H%M%S")
    event_id = f"SAT-{ts_str}-{abs(hash(asset_id + source)) % 100000:05d}"

    return {
        "bot":                  "SATELLITE_BOT",
        "event_id":             event_id,
        "source":               source,
        "timestamp":            ts,
        "asset_id":             asset_id,
        "zone":                 zone,
        "anomaly_type":         anomaly_type,
        "anomaly_score":        score,
        "severity":             severity,
        "evidence_description": evidence,
        "is_anomalous":         is_anomalous,
        "raw":                  raw_event,
    }


def process_batch(events: list[dict]) -> list[dict]:
    """Process a list of raw telemetry records."""
    return [process_telemetry(e) for e in events]


def filter_anomalous(events: list[dict]) -> list[dict]:
    """Return only events with is_anomalous=True (for Fusion Bot input)."""
    return [e for e in events if e.get("is_anomalous", False)]
