# Bot 4 — Fusion & Decision Bot
#
# This is the most important bot in the ThreatNexus architecture.
#
# It receives the normalised outputs from the three source bots:
#   - Bot 1 (Cyber/SIEM Bot)     → CyberEvents
#   - Bot 2 (Intelligence Bot)   → IntelligenceEvents
#   - Bot 3 (Satellite Bot)      → SatelliteEvents
#
# And produces:
#   1. Cross-source correlation (shared entities, indicators, time windows)
#   2. Evidence Matrix — which sources corroborate each finding
#   3. False-positive likelihood score using cross-source evidence
#   4. Multi-source risk score (weighted by evidence type)
#   5. MITRE ATT&CK technique consensus across bots
#   6. Priority classification (CRITICAL / HIGH / MEDIUM / LOW)
#   7. BLUF (Bottom Line Up Front) summary
#
# Design principle (from the mentor review):
#   "Don't have all four bots do the same thing."
#   Each bot adds independent evidence. The Fusion Bot's job is to determine
#   whether independent evidence streams AGREE — and score the certainty of
#   that agreement.
#
# UNCERTAIN state: the Fusion Bot explicitly produces an UNCERTAIN verdict
# when evidence is mixed. Never force every alert into TRUE/FALSE.
#
# Risk score formula (configurable weights):
#   cyber_evidence        20%
#   intel_corroboration   20%
#   satellite_evidence    15%
#   historical_behaviour  15%
#   cross_source_corr     15%
#   asset_criticality     10%
#   recency                5%

from datetime import datetime, timedelta
from typing import Optional

from services.mitre_mapper import map_event, TACTIC_ORDER

# ── Configurable fusion weights ───────────────────────────────────────────────
# These are exposed as config parameters in the admin API so analysts can
# tune them based on operational feedback without code changes.

DEFAULT_WEIGHTS = {
    "cyber_evidence":       0.20,
    "intel_corroboration":  0.20,
    "satellite_evidence":   0.15,
    "historical_behaviour": 0.15,
    "cross_source_corr":    0.15,
    "asset_criticality":    0.10,
    "recency":              0.05,
}

# FP score factors — these contribute to the FALSE-POSITIVE probability
# (positive = evidence of FP, negative = evidence of genuine threat)
_FP_FACTOR_WEIGHTS = {
    "no_intel_corroboration":    +18.0,  # no TI report links this indicator
    "no_cross_source_support":   +15.0,  # only one source sees this
    "known_benign_pattern":      +12.0,  # event type is noise-prone
    "no_satellite_context":       +5.0,  # no satellite evidence (weak signal)
    "intel_strong_positive":     -25.0,  # high-confidence TI matches
    "cyber_high_severity":       -15.0,  # EDR/SIEM sees critical event
    "satellite_corroborates":    -12.0,  # satellite anomaly at same time
    "multi_source_agreement":    -20.0,  # 3+ sources agree
    "analyst_history_tp":        -18.0,  # analysts confirmed similar before
    "analyst_history_fp":        +18.0,  # analysts dismissed similar before
}

# Thresholds for final FP classification
_FP_GENUINE_THRESHOLD  = 25.0   # FP score ≤ 25 → GENUINE
_FP_UNCERTAIN_THRESHOLD = 55.0  # FP score 26-55 → UNCERTAIN
# FP score > 55 → LIKELY_FALSE_POSITIVE

# Time window within which events from different bots are considered coincident
_COINCIDENCE_WINDOW = timedelta(minutes=15)

# Criticality → 0-100 numeric
_CRITICALITY_MAP = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}


def _time_coincidence_score(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
) -> float:
    """
    Measure how tightly events from different sources cluster in time.
    Returns 0.0-1.0: 1.0 means all sources have events within the coincidence window.
    """
    if not cyber_events:
        return 0.0
    cyber_times = [e["timestamp"] for e in cyber_events]
    intel_times = [e["timestamp"] for e in intel_events if e.get("timestamp")]
    sat_times   = [e["timestamp"] for e in sat_events   if e.get("timestamp")]

    sources_coincident = 1  # cyber is always present here
    if intel_times:
        for ct in cyber_times:
            if any(abs((it - ct).total_seconds()) <= _COINCIDENCE_WINDOW.total_seconds() for it in intel_times):
                sources_coincident += 1
                break
    if sat_times:
        for ct in cyber_times:
            if any(abs((st - ct).total_seconds()) <= _COINCIDENCE_WINDOW.total_seconds() for st in sat_times):
                sources_coincident += 1
                break

    return sources_coincident / 3.0


def _indicator_overlap(
    cyber_events: list[dict],
    intel_events: list[dict],
) -> float:
    """
    Fraction of cyber IOCs that appear in intelligence reports.
    Returns 0.0-1.0.
    """
    cyber_ioc_values: set[str] = set()
    for ev in cyber_events:
        for ioc in ev.get("iocs", []):
            cyber_ioc_values.add(ioc.get("value", "").lower())

    if not cyber_ioc_values:
        return 0.0

    intel_ioc_values: set[str] = set()
    for ev in intel_events:
        for ioc in ev.get("indicators", []):
            intel_ioc_values.add(ioc.get("value", "").lower())

    if not intel_ioc_values:
        return 0.0

    overlap = cyber_ioc_values & intel_ioc_values
    return len(overlap) / len(cyber_ioc_values)


def _mitre_consensus(
    cyber_events: list[dict],
    intel_events: list[dict],
) -> list[dict]:
    """
    Collect all MITRE technique mappings from both bots and deduplicate.
    Returns the agreed-upon set of techniques, ordered by TACTIC_ORDER.
    """
    seen_ids: set[str] = set()
    techniques: list[dict] = []

    for ev in cyber_events:
        m = ev.get("mitre_candidate")
        if m and m["technique_id"] not in seen_ids:
            techniques.append(m)
            seen_ids.add(m["technique_id"])

    for ev in intel_events:
        for m in ev.get("mitre_techniques", []):
            if m and m["technique_id"] not in seen_ids:
                techniques.append(m)
                seen_ids.add(m["technique_id"])

    # Sort by kill-chain order
    tactic_index = {t: i for i, t in enumerate(TACTIC_ORDER)}
    techniques.sort(key=lambda m: tactic_index.get(m.get("tactic", ""), 99))
    return techniques


def _build_evidence_matrix(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
    time_score: float,
    ioc_overlap: float,
) -> dict:
    """
    Build the evidence matrix that explains what each source contributed.
    This is the key explainability feature of the Fusion Bot.
    """
    cyber_sources  = list({e.get("source", "CYBER_SENSOR") for e in cyber_events})
    intel_sources  = list({e.get("source", "THREAT_INTEL") for e in intel_events})
    sat_sources    = list({e.get("source", "SATELLITE")    for e in sat_events})

    return {
        "cyber": {
            "present":     bool(cyber_events),
            "event_count": len(cyber_events),
            "sources":     cyber_sources,
            "event_types": list({e.get("event_type", "Unknown") for e in cyber_events}),
        },
        "intelligence": {
            "present":        bool(intel_events),
            "report_count":   len(intel_events),
            "sources":        intel_sources,
            "behaviours":     list({b for e in intel_events for b in e.get("behaviours", [])}),
            "ioc_overlap_pct": round(ioc_overlap * 100, 1),
        },
        "satellite": {
            "present":       bool(sat_events),
            "event_count":   len(sat_events),
            "sources":       sat_sources,
            "anomaly_types": list({e.get("anomaly_type") for e in sat_events}),
            "max_anomaly_score": max((e.get("anomaly_score", 0) for e in sat_events), default=0),
        },
        "time_coincidence_score": round(time_score * 100, 1),
        "sources_corroborating":  sum([
            bool(cyber_events), bool(intel_events), bool(sat_events)
        ]),
    }


def _compute_risk_score(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
    ioc_overlap: float,
    time_score: float,
    asset_criticality: str = "LOW",
    weights: Optional[dict] = None,
) -> dict:
    """
    Compute a weighted 0-100 fusion risk score from all evidence streams.
    Returns the score, its priority and a full breakdown.
    """
    w = weights or DEFAULT_WEIGHTS

    # Cyber evidence (0-100): from highest severity + cyber_confidence
    cyber_score = 0.0
    if cyber_events:
        sev_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
        max_sev = max(sev_map.get(e.get("severity", "LOW"), 20) for e in cyber_events)
        max_conf = max(e.get("cyber_confidence", 0.5) for e in cyber_events)
        cyber_score = (max_sev * 0.6 + max_conf * 100 * 0.4)

    # Intel corroboration (0-100): from confidence + IOC overlap
    intel_score = 0.0
    if intel_events:
        max_conf = max(e.get("confidence", 0.5) for e in intel_events)
        intel_score = max_conf * 70 + ioc_overlap * 30

    # Satellite evidence (0-100): from anomaly scores of anomalous events
    sat_score = 0.0
    anomalous = [e for e in sat_events if e.get("is_anomalous")]
    if anomalous:
        max_anom = max(e.get("anomaly_score", 0) for e in anomalous)
        sat_score = max_anom * 100

    # Historical behaviour (0-100): based on how many sources have history
    hist_score = min(len(intel_events) * 15 + ioc_overlap * 40, 100.0)

    # Cross-source correlation (0-100): time coincidence + source agreement
    cross_score = time_score * 100

    # Asset criticality
    asset_score = _CRITICALITY_MAP.get(asset_criticality.upper(), 20)

    # Recency: all sources have events within the window
    recency_score = 100.0 if time_score >= 0.67 else time_score * 100

    raw = (
        w["cyber_evidence"]       * cyber_score
        + w["intel_corroboration"]  * intel_score
        + w["satellite_evidence"]   * sat_score
        + w["historical_behaviour"] * hist_score
        + w["cross_source_corr"]    * cross_score
        + w["asset_criticality"]    * asset_score
        + w["recency"]              * recency_score
    )
    risk_score = round(min(max(raw, 0.0), 100.0), 2)

    if risk_score >= 80:
        priority = "CRITICAL"
    elif risk_score >= 60:
        priority = "HIGH"
    elif risk_score >= 30:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "risk_score": risk_score,
        "priority": priority,
        "breakdown": {
            "cyber_evidence":       round(cyber_score, 1),
            "intel_corroboration":  round(intel_score, 1),
            "satellite_evidence":   round(sat_score, 1),
            "historical_behaviour": round(hist_score, 1),
            "cross_source_corr":    round(cross_score, 1),
            "asset_criticality":    asset_score,
            "recency":              round(recency_score, 1),
            "weights":              w,
        },
    }


def _compute_fp_probability(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
    ioc_overlap: float,
    time_score: float,
    analyst_history: Optional[dict] = None,
) -> dict:
    """
    Estimate the probability that this fusion result is a false positive.

    Returns a dict with:
        fp_score     0-100 (higher = more likely FP)
        fp_label     LIKELY_FALSE_POSITIVE | UNCERTAIN | GENUINE_THREAT
        reasons      list of human-readable explanation strings
        factors      dict of factor scores applied
    """
    score = 50.0  # neutral prior
    reasons: list[str] = []
    factors: dict[str, float] = {}

    sources_present = sum([bool(cyber_events), bool(intel_events), bool(sat_events)])

    # Multi-source agreement is the strongest driver
    if sources_present >= 3:
        score += _FP_FACTOR_WEIGHTS["multi_source_agreement"]
        factors["multi_source_agreement"] = _FP_FACTOR_WEIGHTS["multi_source_agreement"]
        reasons.append(f"All 3 independent sources corroborate the activity (cyber, intelligence, satellite)")

    elif sources_present == 1:
        score += _FP_FACTOR_WEIGHTS["no_cross_source_support"]
        factors["no_cross_source_support"] = _FP_FACTOR_WEIGHTS["no_cross_source_support"]
        reasons.append("Only 1 source reports this activity — no cross-source corroboration")

    # Intel corroboration
    if intel_events and ioc_overlap > 0.3:
        score += _FP_FACTOR_WEIGHTS["intel_strong_positive"]
        factors["intel_strong_positive"] = _FP_FACTOR_WEIGHTS["intel_strong_positive"]
        reasons.append(f"Threat intelligence confirms {ioc_overlap:.0%} of cyber indicators")
    elif not intel_events:
        score += _FP_FACTOR_WEIGHTS["no_intel_corroboration"]
        factors["no_intel_corroboration"] = _FP_FACTOR_WEIGHTS["no_intel_corroboration"]
        reasons.append("No threat-intelligence report references these indicators")

    # Cyber severity
    if cyber_events:
        sev_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
        max_sev = max(sev_map.get(e.get("severity", "LOW"), 20) for e in cyber_events)
        if max_sev >= 80:
            score += _FP_FACTOR_WEIGHTS["cyber_high_severity"]
            factors["cyber_high_severity"] = _FP_FACTOR_WEIGHTS["cyber_high_severity"]
            reasons.append(f"High-severity cyber event ({max_sev}/100) reported by endpoint/network sensor")

    # Satellite corroboration
    anomalous_sat = [e for e in sat_events if e.get("is_anomalous")]
    if anomalous_sat and time_score > 0.5:
        score += _FP_FACTOR_WEIGHTS["satellite_corroborates"]
        factors["satellite_corroborates"] = _FP_FACTOR_WEIGHTS["satellite_corroborates"]
        reasons.append(
            f"Satellite anomaly ({anomalous_sat[0].get('anomaly_type', 'anomaly')}) "
            f"observed within {_COINCIDENCE_WINDOW.seconds//60}-minute window"
        )
    elif not anomalous_sat:
        score += _FP_FACTOR_WEIGHTS["no_satellite_context"]
        factors["no_satellite_context"] = _FP_FACTOR_WEIGHTS["no_satellite_context"]

    # Analyst history
    hist = analyst_history or {}
    tp = hist.get("true_positives", 0)
    fp = hist.get("false_positives", 0)
    if fp > tp and (tp + fp) >= 2:
        score += _FP_FACTOR_WEIGHTS["analyst_history_fp"]
        factors["analyst_history_fp"] = _FP_FACTOR_WEIGHTS["analyst_history_fp"]
        reasons.append(f"Analysts previously classified {fp} similar events as false positive")
    elif tp > fp and (tp + fp) >= 2:
        score += _FP_FACTOR_WEIGHTS["analyst_history_tp"]
        factors["analyst_history_tp"] = _FP_FACTOR_WEIGHTS["analyst_history_tp"]
        reasons.append(f"Analysts confirmed {tp} similar previous events as genuine")

    # Noise-prone event types with no corroboration
    noise_prone = {"Port Scan", "Suspicious Login", "Reconnaissance", "DDoS"}
    cyber_types = {e.get("event_type") for e in cyber_events}
    if cyber_types and cyber_types.issubset(noise_prone) and not intel_events:
        score += _FP_FACTOR_WEIGHTS["known_benign_pattern"]
        factors["known_benign_pattern"] = _FP_FACTOR_WEIGHTS["known_benign_pattern"]
        reasons.append(f"Event type(s) {', '.join(cyber_types)} commonly produce benign noise without corroboration")

    fp_score = round(min(max(score, 0.0), 100.0), 1)

    if fp_score <= _FP_GENUINE_THRESHOLD:
        fp_label = "GENUINE_THREAT"
    elif fp_score <= _FP_UNCERTAIN_THRESHOLD:
        fp_label = "UNCERTAIN"
    else:
        fp_label = "LIKELY_FALSE_POSITIVE"

    return {
        "fp_score":    fp_score,
        "fp_label":    fp_label,
        "reasons":     reasons[:5],
        "factors":     factors,
    }


def _build_bluf_data(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
    mitre_techniques: list[dict],
    risk: dict,
    fp: dict,
    evidence_matrix: dict,
    asset_criticality: str = "LOW",
) -> dict:
    """
    Build the structured data bundle that ai_engine uses to generate the BLUF.
    Includes every field the BLUF template and Bob prompt expect.
    """
    # Representative source IP from cyber events
    src_ip = next((e.get("src_ip", "unknown") for e in cyber_events), "unknown")
    entity = next((e.get("entity", "unknown") for e in cyber_events), "unknown")

    # Primary event type from highest-severity cyber event
    primary_event = "Unknown"
    if cyber_events:
        sev_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
        top = max(cyber_events, key=lambda e: sev_map.get(e.get("severity", "LOW"), 20))
        primary_event = top.get("event_type", "Unknown")

    # IOC reputation from intelligence bot
    max_intel_conf = max((e.get("confidence", 0) for e in intel_events), default=0.0)

    # Correlation score from cross-source evidence
    corr_score = evidence_matrix["time_coincidence_score"]

    verdict_reasons = fp["reasons"]

    return {
        "source_ip":         src_ip,
        "event_type":        primary_event,
        "priority":          risk["priority"],
        "risk_score":        risk["risk_score"],
        "severity":          cyber_events[0].get("severity", "MEDIUM") if cyber_events else "MEDIUM",
        "asset_hostname":    entity,
        "asset_criticality": asset_criticality,
        "ioc_reputation":    max_intel_conf * 100,
        "ioc_confidence":    max_intel_conf * 100,
        "threat_type":       None,
        "correlation_score": corr_score,
        "verdict":           fp["fp_label"],
        "verdict_reasons":   verdict_reasons,
        # Fusion-specific additions
        "sources_corroborating": evidence_matrix["sources_corroborating"],
        "mitre_techniques":      mitre_techniques,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def fuse(
    cyber_events: list[dict],
    intel_events: list[dict],
    sat_events: list[dict],
    asset_criticality: str = "LOW",
    analyst_history: Optional[dict] = None,
    weights: Optional[dict] = None,
) -> dict:
    """
    The main entry point for the Fusion Bot.

    Accepts normalised output from the three source bots and produces a single
    FusionResult dict representing the combined intelligence picture.

    Returns:
        {
            "bot":              "FUSION_BOT",
            "timestamp":        datetime,         # analysis timestamp
            "mitre_techniques": list[dict],       # consensus ATT&CK techniques
            "evidence_matrix":  dict,             # which sources contributed what
            "risk":             dict,             # score + priority + breakdown
            "fp":               dict,             # fp_score, fp_label, reasons
            "bluf_data":        dict,             # structured data for ai_engine
            "sources_present":  int,             # 1, 2, or 3
            "correlation_confidence": float,     # 0-100
        }
    """
    sat_anomalous = [e for e in sat_events if e.get("is_anomalous", False)]
    time_score    = _time_coincidence_score(cyber_events, intel_events, sat_anomalous)
    ioc_overlap   = _indicator_overlap(cyber_events, intel_events)
    mitre         = _mitre_consensus(cyber_events, intel_events)
    evidence      = _build_evidence_matrix(cyber_events, intel_events, sat_anomalous, time_score, ioc_overlap)
    risk          = _compute_risk_score(cyber_events, intel_events, sat_anomalous, ioc_overlap, time_score, asset_criticality, weights)
    fp            = _compute_fp_probability(cyber_events, intel_events, sat_anomalous, ioc_overlap, time_score, analyst_history)
    bluf_data     = _build_bluf_data(cyber_events, intel_events, sat_anomalous, mitre, risk, fp, evidence, asset_criticality)

    # Cross-source correlation confidence
    corr_conf = round(
        (time_score * 40 + ioc_overlap * 40 + min(evidence["sources_corroborating"] / 3.0, 1.0) * 20),
        1
    )

    return {
        "bot":                    "FUSION_BOT",
        "timestamp":              datetime.utcnow(),
        "cyber_events":           cyber_events,
        "intel_events":           intel_events,
        "satellite_events":       sat_anomalous,
        "mitre_techniques":       mitre,
        "evidence_matrix":        evidence,
        "risk":                   risk,
        "fp":                     fp,
        "bluf_data":              bluf_data,
        "sources_present":        evidence["sources_corroborating"],
        "correlation_confidence": corr_conf,
    }


def get_default_weights() -> dict:
    """Return the current default fusion weights (exposed via admin API)."""
    return dict(DEFAULT_WEIGHTS)
