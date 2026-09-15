# False-positive classifier – decides whether an alert is a GENUINE_THREAT,
# a LIKELY_FALSE_POSITIVE, or NEEDS_REVIEW by an analyst.
#
# It is deliberately explainable: every verdict carries the list of signals
# that produced it so the BLUF summary (and the UI) can show *why* an alert
# was suppressed or escalated.  Analyst triage feedback feeds back in, so the
# more alerts a team labels the more accurate the verdicts become.

from typing import Optional
from sqlalchemy.orm import Session

from models import Alert
from services.risk_engine import BEHAVIORAL_SUSPICION_MAP, CRITICALITY_MAP

GENUINE_THREAT        = "GENUINE_THREAT"
LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
NEEDS_REVIEW          = "NEEDS_REVIEW"

VERDICT_VALUES = {GENUINE_THREAT, LIKELY_FALSE_POSITIVE, NEEDS_REVIEW}

# Score thresholds on the 0-100 "genuineness" scale
_GENUINE_THRESHOLD = 60.0
_FP_THRESHOLD      = 32.0

# Event types that are common benign noise when nothing else corroborates them
_NOISE_PRONE = {"Port Scan", "Suspicious Login", "Reconnaissance", "Unknown", "DDoS"}


def analyst_history(db: Session, source_ip: str, event_type: str, exclude_id: Optional[int] = None) -> dict:
    """
    Count how analysts previously labelled alerts from the same source_ip,
    and from the same source_ip + event_type.  Used as a learning signal.
    """
    q = db.query(Alert).filter(Alert.source_ip == source_ip)
    if exclude_id is not None:
        q = q.filter(Alert.id != exclude_id)
    rows = q.all()

    def _count(subset):
        tp = sum(1 for a in subset if a.feedback in ("TRUE_POSITIVE", "ESCALATED"))
        fp = sum(1 for a in subset if a.feedback == "FALSE_POSITIVE")
        return tp, fp

    ip_tp, ip_fp = _count(rows)
    same = [a for a in rows if a.event_type == event_type]
    ev_tp, ev_fp = _count(same)
    return {
        "ip_true_positive": ip_tp, "ip_false_positive": ip_fp,
        "event_true_positive": ev_tp, "event_false_positive": ev_fp,
    }


def classify(
    *,
    ioc_reputation: float,
    ioc_found: bool,
    asset_criticality: str,
    event_type: str,
    severity: str,
    correlation_count: int,
    is_attack_chain: bool,
    history: Optional[dict] = None,
    own_feedback: Optional[str] = None,
) -> dict:
    """
    Return {"verdict", "confidence", "score", "reasons"}.

    score is 0-100 where 100 = certainly genuine.  reasons is an ordered list
    of short human-readable strings explaining the strongest signals.
    """
    history = history or {}
    reasons: list[str] = []

    # ── 1. Threat intelligence (35 %) ────────────────────────────────────────
    ti = 0.35 * ioc_reputation
    if ioc_reputation >= 80:
        reasons.append(f"Source matches a known-malicious indicator ({ioc_reputation:.0f}/100 reputation)")
    elif ioc_reputation >= 40:
        reasons.append(f"Source has a moderate threat reputation ({ioc_reputation:.0f}/100)")
    elif not ioc_found:
        reasons.append("Source IP is not in any threat-intelligence feed")

    # ── 2. Correlation (20 %) + attack-chain bonus ──────────────────────────
    corr_norm = min(correlation_count / 5.0, 1.0) * 100.0
    corr = 0.20 * corr_norm
    if is_attack_chain:
        corr += 15.0
        reasons.append("Part of a multi-stage attack chain spanning 3+ MITRE tactics")
    elif correlation_count >= 3:
        reasons.append(f"Corroborated by {correlation_count} related alerts on the same source/asset")
    elif correlation_count == 0:
        reasons.append("Isolated event — no corroborating alerts in the last 24 h")

    # ── 3. Asset criticality (15 %) ─────────────────────────────────────────
    crit = CRITICALITY_MAP.get(asset_criticality.upper(), 20)
    asset = 0.15 * crit
    if crit >= 80:
        reasons.append(f"Targets a {asset_criticality}-criticality asset")

    # ── 4. Behavioural suspicion (15 %) ─────────────────────────────────────
    behav_raw = BEHAVIORAL_SUSPICION_MAP.get(event_type, 40)
    behav = 0.15 * behav_raw
    if event_type in _NOISE_PRONE and ioc_reputation < 40 and correlation_count < 2:
        behav *= 0.4
        reasons.append(f"{event_type} from an unknown source with no corroboration is typically benign noise")

    # ── 5. Severity as reported by the feed (15 %) ──────────────────────────
    sev_map = {"LOW": 20, "MEDIUM": 50, "HIGH": 80, "CRITICAL": 100}
    sev = 0.15 * sev_map.get(severity.upper(), 40)

    score = ti + corr + asset + behav + sev

    # ── 6. Analyst learning signal (±20) ────────────────────────────────────
    ev_tp = history.get("event_true_positive", 0)
    ev_fp = history.get("event_false_positive", 0)
    ip_tp = history.get("ip_true_positive", 0)
    ip_fp = history.get("ip_false_positive", 0)
    labelled = ev_tp + ev_fp
    if labelled:
        shift = 20.0 * (ev_tp - ev_fp) / labelled
        score += shift
        if ev_fp > ev_tp:
            reasons.append(f"Analysts marked {ev_fp} previous {event_type} alert(s) from this source as false positive")
        elif ev_tp > ev_fp:
            reasons.append(f"Analysts confirmed {ev_tp} previous {event_type} alert(s) from this source as genuine")
    elif ip_tp + ip_fp:
        shift = 10.0 * (ip_tp - ip_fp) / (ip_tp + ip_fp)
        score += shift
        if ip_tp > ip_fp:
            reasons.append(f"Analysts previously confirmed activity from this source as genuine ({ip_tp}×)")
        elif ip_fp > ip_tp:
            reasons.append(f"Analysts previously dismissed activity from this source ({ip_fp}× false positive)")

    score = max(0.0, min(100.0, score))

    # ── 7. Hard overrides ───────────────────────────────────────────────────
    if own_feedback == "FALSE_POSITIVE":
        return _result(LIKELY_FALSE_POSITIVE, 97.0, score,
                       ["Analyst marked this alert as a false positive"] + reasons)
    if own_feedback in ("TRUE_POSITIVE", "ESCALATED"):
        return _result(GENUINE_THREAT, 97.0, score,
                       ["Analyst confirmed this alert as a genuine threat"] + reasons)
    if ioc_reputation >= 85 and score < _GENUINE_THRESHOLD:
        # never suppress traffic from a high-confidence malicious indicator
        score = _GENUINE_THRESHOLD

    # ── 8. Verdict + confidence (distance from nearest threshold) ───────────
    if score >= _GENUINE_THRESHOLD:
        verdict = GENUINE_THREAT
        conf = 55 + (score - _GENUINE_THRESHOLD) / (100 - _GENUINE_THRESHOLD) * 40
    elif score <= _FP_THRESHOLD:
        verdict = LIKELY_FALSE_POSITIVE
        conf = 55 + (_FP_THRESHOLD - score) / _FP_THRESHOLD * 40
    else:
        verdict = NEEDS_REVIEW
        mid = (_GENUINE_THRESHOLD + _FP_THRESHOLD) / 2
        conf = 40 + (1 - abs(score - mid) / ((_GENUINE_THRESHOLD - _FP_THRESHOLD) / 2)) * 20
        reasons.append("Mixed signals — analyst review recommended")

    return _result(verdict, conf, score, reasons)


def _result(verdict: str, confidence: float, score: float, reasons: list[str]) -> dict:
    return {
        "verdict":    verdict,
        "confidence": round(min(max(confidence, 0.0), 99.0), 1),
        "score":      round(score, 1),
        "reasons":    reasons[:5],
    }


def verdict_label(verdict: Optional[str]) -> str:
    return {
        GENUINE_THREAT:        "Genuine threat",
        LIKELY_FALSE_POSITIVE: "Likely false positive",
        NEEDS_REVIEW:          "Needs review",
    }.get(verdict or "", "Unassessed")
