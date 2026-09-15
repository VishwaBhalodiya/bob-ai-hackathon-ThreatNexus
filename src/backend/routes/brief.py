"""
routes/brief.py – Commander-facing roll-ups.

GET /api/brief            prioritised BLUF investigation brief
GET /api/attack-chains    correlated multi-stage chains (last 24 h)
GET /api/mitre/coverage   alert counts per ATT&CK tactic (kill-chain order)
GET /api/mitre/techniques the event_type → technique mapping table
"""
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from models import Alert, Asset
from schemas import (
    AIExplanation, BriefChain, BriefPriority, BriefStats, BriefSuppressed, CommanderBrief,
)
from services import correlation_engine, mitre_mapper, pipeline
from services.fp_classifier import GENUINE_THREAT, LIKELY_FALSE_POSITIVE, NEEDS_REVIEW

router = APIRouter(tags=["brief"])


def _tactic_coverage(alerts: list[Alert]) -> list[dict]:
    counts: dict[str, int] = {}
    for a in alerts:
        t = a.mitre_tactic or mitre_mapper.tactic_for(a.event_type)
        if t:
            counts[t] = counts.get(t, 0) + 1
    return [
        {"tactic": t, "count": counts.get(t, 0)}
        for t in mitre_mapper.TACTIC_ORDER
    ]


@router.get("/api/mitre/techniques")
def mitre_techniques():
    return {"tactic_order": mitre_mapper.TACTIC_ORDER, "techniques": mitre_mapper.all_techniques()}


@router.get("/api/mitre/coverage")
def mitre_coverage(
    open_only: bool = Query(False, description="Only count OPEN / IN_PROGRESS alerts"),
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if open_only:
        q = q.filter(Alert.status != "RESOLVED")
    alerts = q.all()
    techniques: dict[str, dict] = {}
    for a in alerts:
        m = mitre_mapper.map_event(a.event_type)
        if not m:
            continue
        entry = techniques.setdefault(m["technique_id"], {**m, "count": 0, "alert_ids": []})
        entry["count"] += 1
        entry["alert_ids"].append(a.id)
    return {
        "tactics": _tactic_coverage(alerts),
        "techniques": sorted(techniques.values(), key=lambda t: t["count"], reverse=True),
    }


@router.get("/api/attack-chains")
def attack_chains(
    window_hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
):
    chains = correlation_engine.detect_attack_chains(db, window_hours=window_hours)
    asset_names = {a.id: a.hostname for a in db.query(Asset).all()}
    for c in chains:
        c["assets"] = [asset_names.get(i, f"asset-{i}") for i in c["asset_ids"]]
    return {"window_hours": window_hours, "chains": chains}


def _posture(critical: int, chains: int, high: int) -> str:
    if chains and critical:
        return "CRITICAL"
    if critical or chains:
        return "ELEVATED"
    if high:
        return "GUARDED"
    return "NORMAL"


@router.get("/api/brief", response_model=CommanderBrief)
def commander_brief(
    limit: int = Query(8, ge=1, le=50, description="Max prioritised items"),
    window_hours: int = Query(72, ge=1, le=720),
    include_resolved: bool = Query(False),
    llm: bool = Query(False, description="Generate each item's BLUF with IBM Bob (slower)"),
    db: Session = Depends(get_db),
):
    """
    Bottom-Line-Up-Front brief for a commander: overall posture and a single
    sentence verdict first, then active attack chains, then the ranked list of
    genuine threats, then the noise that was suppressed and why.
    """
    since = datetime.utcnow() - timedelta(hours=window_hours)
    q = db.query(Alert).filter(Alert.timestamp >= since)
    if not include_resolved:
        q = q.filter(Alert.status != "RESOLVED")
    alerts: list[Alert] = q.all()
    all_alerts_count = db.query(Alert).count()
    assets = {a.id: a for a in db.query(Asset).all()}

    # ── Verdict buckets ──────────────────────────────────────────────────────
    genuine   = [a for a in alerts if a.verdict == GENUINE_THREAT]
    fp        = [a for a in alerts if a.verdict == LIKELY_FALSE_POSITIVE]
    review    = [a for a in alerts if (a.verdict or NEEDS_REVIEW) == NEEDS_REVIEW]
    critical  = [a for a in alerts if a.priority == "CRITICAL" and a.verdict != LIKELY_FALSE_POSITIVE]
    high      = [a for a in alerts if a.priority == "HIGH" and a.verdict != LIKELY_FALSE_POSITIVE]

    # ── Attack chains ────────────────────────────────────────────────────────
    chains_raw = [
        c for c in correlation_engine.detect_attack_chains(db, window_hours=window_hours)
        if c["is_multi_stage"]
    ]
    chains: list[BriefChain] = []
    for c in chains_raw:
        names = [assets[i].hostname for i in c["asset_ids"] if i in assets]
        crit_assets = [assets[i] for i in c["asset_ids"] if i in assets and assets[i].criticality in ("CRITICAL", "HIGH")]
        target = names[0] if names else "multiple hosts"
        stages = " → ".join(c["tactics"])
        action = {
            "CRITICAL": f"isolate {target} now",
            "HIGH":     f"contain {target} this shift",
        }.get(c["priority"], f"investigate {target}")
        chains.append(BriefChain(
            source_ip=c["source_ip"], alert_ids=c["alert_ids"], alert_count=c["alert_count"],
            assets=names, tactics=c["tactics"], event_types=c["event_types"],
            first_seen=c["first_seen"], last_seen=c["last_seen"],
            max_risk_score=c["max_risk_score"], is_multi_stage=True,
            priority=c["priority"], genuine_count=c["genuine_count"],
            bottom_line=(
                f"{c['priority']} — {action}; {c['source_ip']} has progressed through "
                f"{len(c['tactics'])} ATT&CK stages ({stages}) in {c['alert_count']} correlated alerts"
                + (f", including {len(crit_assets)} high-value asset(s)" if crit_assets else "") + "."
            ),
        ))
    chain_alert_ids = {i for c in chains for i in c.alert_ids}

    # ── Ranked priorities (genuine first, then needs-review; never likely-FP) ─
    # Correlated duplicates (same actor, same technique, same target reported
    # by several feeds) collapse to the single highest-scoring alert so the
    # commander sees distinct threats, not repeats.
    ranked_all = sorted(
        [a for a in alerts if a.verdict != LIKELY_FALSE_POSITIVE],
        key=lambda a: (
            a.verdict == GENUINE_THREAT,
            a.id in chain_alert_ids,
            a.risk_score,
        ),
        reverse=True,
    )
    seen_keys: set = set()
    ranked: list[Alert] = []
    for a in ranked_all:
        key = (a.source_ip, a.event_type, a.asset_id)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        ranked.append(a)
        if len(ranked) >= limit:
            break

    priorities: list[BriefPriority] = []
    for rank, a in enumerate(ranked, start=1):
        res = pipeline.assess_alert(db, a, with_explanation=True, allow_llm=llm)
        asset = assets.get(a.asset_id)
        m = res["mitre"]
        priorities.append(BriefPriority(
            rank=rank, alert_id=a.id, timestamp=a.timestamp,
            priority=res["risk"]["priority"], risk_score=res["risk"]["risk_score"],
            verdict=res["verdict"]["verdict"], verdict_confidence=res["verdict"]["confidence"],
            event_type=a.event_type, source_ip=a.source_ip, source=a.source or "SIEM",
            asset=asset.hostname if asset else None,
            asset_criticality=asset.criticality if asset else None,
            mitre_technique_id=m["technique_id"] if m else None,
            mitre_tactic=m["tactic"] if m else None,
            is_attack_chain=res["is_attack_chain"] or a.id in chain_alert_ids,
            bluf=AIExplanation(**res["explanation"]),
        ))

    # ── Suppressed noise ─────────────────────────────────────────────────────
    suppressed: list[BriefSuppressed] = []
    for a in sorted(fp, key=lambda a: a.verdict_confidence or 0, reverse=True)[:limit]:
        res = pipeline.assess_alert(db, a, with_explanation=False)
        asset = assets.get(a.asset_id)
        reasons = res["verdict"]["reasons"]
        suppressed.append(BriefSuppressed(
            alert_id=a.id, event_type=a.event_type, source_ip=a.source_ip,
            asset=asset.hostname if asset else None, priority=a.priority,
            verdict_confidence=res["verdict"]["confidence"],
            reason=reasons[0] if reasons else "No corroborating signals",
        ))

    # ── Headline BLUF ────────────────────────────────────────────────────────
    posture = _posture(len(critical), len(chains), len(high))
    crit_assets = sorted({assets[a.asset_id].hostname for a in critical if a.asset_id in assets})
    n_actionable = len(critical) + len(high)
    noise_pct = round(100.0 * len(fp) / len(alerts), 1) if alerts else 0.0

    if posture == "CRITICAL":
        bottom_line = (
            f"CRITICAL — {len(chains)} active multi-stage attack chain(s) and {len(critical)} critical "
            f"alert(s) require immediate containment; highest-value targets: "
            f"{', '.join(crit_assets[:3]) or 'see priorities'}."
        )
    elif posture == "ELEVATED":
        bottom_line = (
            f"ELEVATED — {len(critical)} critical and {len(high)} high-priority genuine alert(s) "
            f"need action this shift; no confirmed multi-stage chain." if not chains else
            f"ELEVATED — {len(chains)} multi-stage attack chain(s) detected; contain before it escalates."
        )
    elif posture == "GUARDED":
        bottom_line = f"GUARDED — {len(high)} high-priority alert(s) warrant investigation; no critical threats."
    else:
        bottom_line = "NORMAL — no genuine critical or high-priority threats in the reporting window."

    sources = {}
    for a in alerts:
        sources[a.source or "SIEM"] = sources.get(a.source or "SIEM", 0) + 1

    situation = (
        f"{len(alerts)} alerts from {len(sources)} feed(s) ({', '.join(sorted(sources))}) in the last "
        f"{window_hours} h; correlation grouped them into {len(chains_raw)} multi-stage chain(s) and "
        f"classified {len(genuine)} as genuine, {len(fp)} as likely false positives and "
        f"{len(review)} as needing analyst review."
    )
    assessment = (
        f"Automated triage suppressed {noise_pct}% of volume as noise, leaving {n_actionable} "
        f"actionable critical/high items. "
        + (f"The most dangerous activity is {chains[0].source_ip} moving through "
           f"{' → '.join(chains[0].tactics)} against {', '.join(chains[0].assets) or 'internal hosts'}."
           if chains else
           f"Highest single risk: alert #{priorities[0].alert_id} ({priorities[0].event_type} on "
           f"{priorities[0].asset or priorities[0].source_ip})." if priorities else
           "No high-risk activity identified.")
    )
    recommendation = (
        (f"1. Isolate {', '.join(chains[0].assets) or 'chain targets'} and block {chains[0].source_ip} at the perimeter. "
         if chains else "")
        + (f"{'2' if chains else '1'}. Work the ranked priorities top-down; each carries its own BLUF and remediation steps. "
           if priorities else "")
        + f"{'3' if chains else '2'}. Review the {len(review)} needs-review item(s) and confirm/dismiss to sharpen future verdicts."
    )

    stats = BriefStats(
        total_alerts=all_alerts_count, open_alerts=len(alerts),
        critical=len(critical), high=len(high),
        genuine=len(genuine), likely_false_positive=len(fp), needs_review=len(review),
        attack_chains=len(chains), noise_reduction_pct=noise_pct,
        sources=sources, window_hours=window_hours,
    )

    return CommanderBrief(
        generated_at=datetime.utcnow(),
        posture=posture,
        bottom_line=bottom_line,
        situation=situation,
        assessment=assessment,
        recommendation=recommendation,
        stats=stats,
        attack_chains=chains,
        priorities=priorities,
        suppressed=suppressed,
        tactic_coverage=_tactic_coverage(alerts),
    )
