# Assessment pipeline – the one place that turns a raw alert into a fully
# enriched, scored, correlated, MITRE-mapped and verdict-tagged record.
#
#   feed → normalise → [assess] → persist
#                       ▲
#   GET /api/alerts/{id} ┘  (re-assessed live so correlation is always fresh)
#   POST /api/analyze     ┘
#   POST /api/alerts/rescore ┘
#
# Keeping every caller on this function guarantees the dashboard list, the
# detail view, the ingest response and the commander brief all agree.

import re
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models import Alert, Asset, IOC, Recommendation, ThreatEvent
from services import (
    ai_engine,
    correlation_engine,
    fp_classifier,
    mitre_mapper,
    risk_engine,
    threat_intelligence,
)
from services.ioc_extractor import extract_iocs


def _lookup_candidates(ioc: dict) -> list[tuple[str, str]]:
    """(type, value) pairs to look up for one extracted IOC."""
    t, v = ioc["type"], ioc["value"]
    out = [(t, v)]
    if t == "URL":
        host = re.sub(r"^https?://", "", v, flags=re.I).split("/")[0].split(":")[0]
        if host:
            out.append(("IP" if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host) else "DOMAIN", host))
    elif t == "EMAIL" and "@" in v:
        out.append(("DOMAIN", v.rsplit("@", 1)[1]))
    return out


def assess(
    db: Session,
    *,
    source_ip: str,
    event_type: str,
    severity: str,
    asset_id: Optional[int] = None,
    timestamp: Optional[datetime] = None,
    alert_id: Optional[int] = None,
    feedback: Optional[str] = None,
    raw_text: Optional[str] = None,
    with_explanation: bool = True,
    allow_llm: bool = True,
) -> dict:
    """
    Run the full enrichment chain for one alert (persisted or not).

    raw_text is the alert's description + raw log; every IOC found in it
    (IPs, domains, URLs, hashes, e-mails) is looked up and the strongest
    reputation drives the score — not just the source IP.

    Returns a dict with: ioc_data, ioc, iocs, asset, correlation_score,
    correlation_count, related_events, is_attack_chain, risk, verdict,
    mitre, alert_data and (optionally) explanation.
    """
    timestamp = timestamp or datetime.utcnow()

    # 1. Threat-intelligence enrichment — source indicator first, then every
    #    IOC extracted from the raw text; the strongest match wins.
    ioc_data = threat_intelligence.lookup_ioc(db, source_ip)
    iocs: list[dict] = [{
        "type": "IP", "value": source_ip, "role": "source",
        "found": bool(ioc_data.get("found")),
        "reputation": ioc_data["reputation"], "confidence": ioc_data.get("confidence", 0.0),
        "threat_type": ioc_data.get("threat_type"),
    }]
    seen_values = {source_ip.lower()}
    for extracted in extract_iocs(raw_text or ""):
        # A URL or e-mail is looked up as-is AND by its host / domain, so intel
        # keyed on "phish-bank.tk" still matches "noreply@phish-bank.tk".
        for ioc_type, value in _lookup_candidates(extracted):
            if value.lower() in seen_values:
                continue
            seen_values.add(value.lower())
            ti = threat_intelligence.lookup_ioc(db, value)
            iocs.append({
                "type": ioc_type, "value": value, "role": "extracted",
                "found": bool(ti.get("found")),
                "reputation": ti["reputation"], "confidence": ti.get("confidence", 0.0),
                "threat_type": ti.get("threat_type"),
            })
    strongest = max(iocs, key=lambda i: i["reputation"])
    if strongest["reputation"] > ioc_data["reputation"]:
        # A domain / hash / URL in the log outranks the source IP — score on it.
        ioc_data = {
            **ioc_data,
            "found": True,
            "reputation": strongest["reputation"],
            "confidence": max(ioc_data.get("confidence", 0.0), strongest["confidence"]),
            "threat_type": strongest["threat_type"] or ioc_data.get("threat_type"),
            "driver": strongest,
        }
    ioc: Optional[IOC] = (
        db.query(IOC).filter(IOC.id == ioc_data["ioc_id"]).first()
        if ioc_data.get("ioc_id") else None
    )

    # 2. Asset context
    asset: Optional[Asset] = (
        db.query(Asset).filter(Asset.id == asset_id).first() if asset_id else None
    )
    asset_criticality = asset.criticality if asset else "LOW"

    # 3. Correlation — 24 h cluster (feeds the risk formula) and the narrow
    #    ±10 min window (feeds the timeline + attack-chain classifier)
    correlated = correlation_engine.get_correlated_alerts(db, source_ip, asset_id)
    correlation_count = len([a for a in correlated if a.id != alert_id])
    correlation_score = round(min(correlation_count / 10.0, 1.0) * 100.0, 2)

    related_events = correlation_engine.get_related_events_at(
        db, timestamp, source_ip, asset_id, exclude_id=alert_id
    )
    is_attack_chain = correlation_engine.classify_attack_chain(event_type, related_events)

    # 4. Risk score
    risk = risk_engine.calculate_risk(
        severity=severity,
        ioc_reputation=ioc_data["reputation"],
        asset_criticality=asset_criticality,
        event_type=event_type,
        correlation_score=correlation_score,
    )

    # 5. Genuine-vs-false-positive verdict (learns from analyst feedback)
    history = fp_classifier.analyst_history(db, source_ip, event_type, exclude_id=alert_id)
    verdict = fp_classifier.classify(
        ioc_reputation=ioc_data["reputation"],
        ioc_found=bool(ioc_data.get("found")),
        asset_criticality=asset_criticality,
        event_type=event_type,
        severity=severity,
        correlation_count=correlation_count,
        is_attack_chain=is_attack_chain,
        history=history,
        own_feedback=feedback,
    )
    driver = ioc_data.get("driver")
    if driver:
        # The classifier described the *effective* reputation as the source;
        # replace that line with the indicator that actually drove it.
        verdict["reasons"] = [r for r in verdict["reasons"] if not r.startswith("Source ")]
        verdict["reasons"].insert(0, (
            f"Log references known-malicious {driver['type'].lower()} {driver['value']} "
            f"({driver['reputation']:.0f}/100{', ' + driver['threat_type'] if driver['threat_type'] else ''})"
        ))
        verdict["reasons"] = verdict["reasons"][:5]

    # 6. MITRE ATT&CK mapping
    mitre = mitre_mapper.map_event(event_type)

    alert_data = {
        "source_ip":         source_ip,
        "event_type":        event_type,
        "priority":          risk["priority"],
        "risk_score":        risk["risk_score"],
        "severity":          severity,
        "asset_hostname":    asset.hostname if asset else "unknown",
        "asset_criticality": asset_criticality,
        "ioc_reputation":    ioc_data["reputation"],
        "ioc_confidence":    ioc_data.get("confidence", 0.0),
        "threat_type":       ioc_data.get("threat_type"),
        "correlation_score": correlation_score,
        "verdict":           verdict["verdict"],
        "verdict_reasons":   verdict["reasons"],
    }

    result = {
        "ioc_data":          ioc_data,
        "ioc":               ioc,
        "iocs":              iocs,
        "asset":             asset,
        "correlation_score": correlation_score,
        "correlation_count": correlation_count,
        "related_events":    related_events,
        "is_attack_chain":   is_attack_chain,
        "risk":              risk,
        "verdict":           verdict,
        "mitre":             mitre,
        "alert_data":        alert_data,
    }

    # 7. BLUF explanation (LLM with template fallback)
    if with_explanation:
        result["explanation"] = ai_engine.generate_explanation(alert_data, allow_llm=allow_llm)

    return result


def assess_alert(db: Session, alert: Alert, **kwargs) -> dict:
    """assess() for an existing Alert row — fills every argument from the row."""
    return assess(
        db,
        source_ip=alert.source_ip, event_type=alert.event_type, severity=alert.severity,
        asset_id=alert.asset_id, timestamp=alert.timestamp, alert_id=alert.id,
        feedback=alert.feedback,
        raw_text=f"{alert.description or ''} {alert.raw_log or ''}",
        **kwargs,
    )


def apply_to_alert(alert: Alert, assessment: dict) -> None:
    """Copy the scored fields of an assessment onto an Alert ORM row."""
    alert.iocs                = assessment["iocs"]
    alert.risk_score          = assessment["risk"]["risk_score"]
    alert.priority            = assessment["risk"]["priority"]
    alert.verdict             = assessment["verdict"]["verdict"]
    alert.verdict_confidence  = assessment["verdict"]["confidence"]
    mitre = assessment["mitre"]
    alert.mitre_technique_id  = mitre["technique_id"] if mitre else None
    alert.mitre_technique     = mitre["technique"]    if mitre else None
    alert.mitre_tactic        = mitre["tactic"]       if mitre else None


def persist_new_alert(db: Session, record: dict, assessment: dict) -> Alert:
    """
    Create the Alert row plus its ThreatEvent and Recommendation children
    from a normalised feed record and its assessment.  Caller commits.
    """
    alert = Alert(
        timestamp      = record["timestamp"],
        source_ip      = record["source_ip"],
        destination_ip = record.get("destination_ip"),
        event_type     = record["event_type"],
        severity       = record["severity"],
        asset_id       = record.get("asset_id"),
        status         = "OPEN",
        source         = record.get("source", "SIEM"),
        feed_format    = record.get("feed_format"),
        raw_log        = record.get("raw_log"),
        description    = record.get("description"),
    )
    apply_to_alert(alert, assessment)
    db.add(alert)
    db.flush()  # get alert.id for the children

    ioc_data = assessment["ioc_data"]
    asset    = assessment["asset"]
    db.add(ThreatEvent(
        alert_id    = alert.id,
        ioc_id      = ioc_data.get("ioc_id"),
        event_type  = alert.event_type,
        description = (
            f"{alert.event_type} detected from {alert.source_ip} "
            f"targeting {asset.hostname if asset else (alert.destination_ip or 'unknown host')}. "
            + (f"IOC identified as {ioc_data['threat_type']}." if ioc_data.get("threat_type") else "")
        ).strip(),
        timestamp   = alert.timestamp,
    ))
    db.add(Recommendation(
        alert_id       = alert.id,
        recommendation = ai_engine.generate_recommendation(assessment["alert_data"]),
        generated_by   = "ai_engine",
    ))
    return alert


def rescore_all(db: Session) -> dict:
    """
    Re-run assess() over every stored alert (oldest first so correlation
    builds up naturally) and persist the refreshed score / verdict / MITRE
    fields.  Returns counts of what changed.
    """
    alerts = db.query(Alert).order_by(Alert.timestamp).all()
    changed_priority = changed_verdict = 0
    for a in alerts:
        res = assess_alert(db, a, with_explanation=False)
        before = (a.priority, a.verdict)
        apply_to_alert(a, res)
        if before[0] != a.priority:
            changed_priority += 1
        if before[1] != a.verdict:
            changed_verdict += 1
    db.commit()
    return {
        "rescored": len(alerts),
        "priority_changed": changed_priority,
        "verdict_changed": changed_verdict,
    }
