"""
routes/ingest.py – Multi-source feed ingestion.

POST /api/ingest           raw feed text (any supported format) → alerts / IOCs
GET  /api/ingest/formats   supported formats + what each maps to
GET  /api/ingest/samples   bundled sample feeds (one per format) for demos
"""
import json
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import get_db
from models import Alert, Asset, IOC
from schemas import (
    AlertResponse, IngestRequest, IngestResponse, IngestSummary, SampleFeed,
)
from services import feed_ingestor, pipeline

router = APIRouter(prefix="/api/ingest", tags=["ingest"])

_SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_feeds")

# Duplicate suppression: the same source→event→destination inside this window
# is treated as one alert even if two feeds both reported it.
_DEDUP_WINDOW = timedelta(seconds=90)

SAMPLES = [
    {
        "name": "Firewall (CEF)",
        "filename": "firewall.cef",
        "format": "cef",
        "source": "Firewall",
        "description": "Palo Alto / Cisco ASA events in ArcSight Common Event Format",
    },
    {
        "name": "IDS / IPS (Suricata syslog)",
        "filename": "ids_suricata.log",
        "format": "syslog",
        "source": "IDS/IPS",
        "description": "Suricata fast-log signatures plus key=value sensor lines",
    },
    {
        "name": "SIEM export (JSON)",
        "filename": "siem_export.json",
        "format": "json",
        "source": "SIEM",
        "description": "Elastic / QRadar style JSON with nested source.ip fields",
    },
    {
        "name": "EDR detections (CSV)",
        "filename": "edr_detections.csv",
        "format": "csv",
        "source": "EDR",
        "description": "Endpoint detection export with free-text detection names",
    },
    {
        "name": "Threat-intel feed (STIX 2.1)",
        "filename": "threat_intel.stix.json",
        "format": "stix",
        "source": "Threat Intel Feed",
        "description": "Indicator bundle — updates the IOC table and re-scores matching alerts",
    },
]


@router.get("/formats")
def list_formats():
    return {
        "formats": [
            {"id": "auto",   "label": "Auto-detect", "description": "Sniff the payload and pick a parser"},
            {"id": "cef",    "label": "CEF",         "description": "ArcSight Common Event Format (firewalls, WAF, proxies)"},
            {"id": "syslog", "label": "Syslog",      "description": "RFC 3164/5424, Suricata/Snort fast-log, key=value"},
            {"id": "json",   "label": "JSON",        "description": "JSON array, object envelope or NDJSON (SIEM/EDR exports)"},
            {"id": "csv",    "label": "CSV",         "description": "Header row + rows (EDR / scanner exports)"},
            {"id": "stix",   "label": "STIX 2.1",    "description": "Indicator bundle → IOC table (threat-intel feeds)"},
        ]
    }


@router.get("/samples", response_model=list[SampleFeed])
def list_samples():
    out = []
    for s in SAMPLES:
        path = os.path.join(_SAMPLE_DIR, s["filename"])
        try:
            with open(path, encoding="utf-8") as fh:
                payload = fh.read()
        except OSError:
            continue
        out.append(SampleFeed(**s, payload=payload))
    return out


def _resolve_asset(db: Session, record: dict) -> int | None:
    """Link a feed record to a known asset by destination IP, then hostname."""
    dst = record.get("destination_ip")
    if dst:
        a = db.query(Asset).filter(Asset.ip_address == dst).first()
        if a:
            return a.id
    host = record.get("hostname")
    if host:
        a = db.query(Asset).filter(Asset.hostname.ilike(host)).first()
        if a:
            return a.id
        a = db.query(Asset).filter(Asset.hostname.ilike(f"{host}%")).first()
        if a:
            return a.id
    return None


def _is_duplicate(db: Session, record: dict) -> bool:
    lo = record["timestamp"] - _DEDUP_WINDOW
    hi = record["timestamp"] + _DEDUP_WINDOW
    q = (
        db.query(Alert)
        .filter(Alert.source_ip == record["source_ip"])
        .filter(Alert.event_type == record["event_type"])
        .filter(Alert.timestamp >= lo, Alert.timestamp <= hi)
    )
    if record.get("destination_ip"):
        q = q.filter(Alert.destination_ip == record["destination_ip"])
    return db.query(q.exists()).scalar()


def _ingest_iocs(db: Session, iocs: list[dict]) -> tuple[int, int, int]:
    """Upsert STIX indicators into the IOC table; re-score alerts that match."""
    added = updated = 0
    touched_values: set[str] = set()
    for i in iocs:
        row = db.query(IOC).filter(IOC.ioc_value == i["ioc_value"]).first()
        if row:
            # keep the stronger signal
            row.reputation  = max(row.reputation or 0, i["reputation"])
            row.confidence  = max(row.confidence or 0, i["confidence"])
            row.threat_type = i["threat_type"] or row.threat_type
            row.last_seen   = max(row.last_seen or i["last_seen"], i["last_seen"])
            updated += 1
        else:
            db.add(IOC(
                ioc_value=i["ioc_value"], ioc_type=i["ioc_type"],
                reputation=i["reputation"], confidence=i["confidence"],
                threat_type=i["threat_type"],
                first_seen=i["first_seen"], last_seen=i["last_seen"],
            ))
            added += 1
        touched_values.add(i["ioc_value"])
    db.flush()

    # New intel changes the picture for every alert from those indicators.
    rescored = 0
    if touched_values:
        # Any alert whose source or extracted IOCs match the new intel.
        candidates = db.query(Alert).all()
        for a in candidates:
            referenced = {a.source_ip} | {i["value"] for i in (a.iocs or [])}
            if not (referenced & touched_values):
                continue
            pipeline.apply_to_alert(a, pipeline.assess_alert(db, a, with_explanation=False))
            rescored += 1
    db.commit()
    return added, updated, rescored


@router.post("", response_model=IngestResponse)
def ingest(req: IngestRequest, db: Session = Depends(get_db)):
    """
    Ingest a raw feed.  Each record is normalised, de-duplicated, linked to an
    asset, enriched against threat intel, correlated with existing alerts,
    risk-scored, MITRE-mapped, and given a genuine/false-positive verdict.
    """
    payload = req.payload
    if not isinstance(payload, str):
        payload = json.dumps(payload)

    try:
        fmt, records = feed_ingestor.parse(payload, req.format, req.source)
    except feed_ingestor.FeedParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    if fmt == "stix":
        added, updated, rescored = _ingest_iocs(db, records)
        return IngestResponse(
            format=fmt, source=req.source or "Threat Intel Feed",
            received=len(records), ingested=0, duplicates=0, skipped=0,
            iocs_added=added, iocs_updated=updated, alerts_rescored=rescored,
            warnings=[] if records else ["No indicator objects found in bundle"],
        )

    created: list[Alert] = []
    duplicates = skipped = 0
    warnings: list[str] = []
    summary = IngestSummary()

    # Oldest first so correlation within the batch builds up naturally.
    for rec in sorted(records, key=lambda r: r["timestamp"]):
        if _is_duplicate(db, rec):
            duplicates += 1
            continue
        rec["asset_id"] = _resolve_asset(db, rec)
        if rec["event_type"] == "Unknown":
            warnings.append(
                f"Could not map event '{(rec.get('raw_event_type') or '')[:60]}' from {rec['source_ip']} "
                f"to a known technique — ingested as Unknown"
            )
        res = pipeline.assess(
            db, source_ip=rec["source_ip"], event_type=rec["event_type"],
            severity=rec["severity"], asset_id=rec["asset_id"], timestamp=rec["timestamp"],
            raw_text=f"{rec.get('description') or ''} {rec.get('raw_log') or ''}",
            with_explanation=False,
        )
        alert = pipeline.persist_new_alert(db, rec, res)
        db.flush()
        created.append(alert)

        p = alert.priority.lower()
        if hasattr(summary, p):
            setattr(summary, p, getattr(summary, p) + 1)
        v = alert.verdict
        if v == "GENUINE_THREAT":
            summary.genuine += 1
        elif v == "LIKELY_FALSE_POSITIVE":
            summary.likely_false_positive += 1
        else:
            summary.needs_review += 1
        if res["is_attack_chain"]:
            summary.attack_chains += 1

    db.commit()

    # Newly ingested alerts change the correlation picture of their neighbours;
    # refresh the siblings so the dashboard list stays consistent.
    touched_ips = {a.source_ip for a in created}
    if touched_ips:
        for a in db.query(Alert).filter(Alert.source_ip.in_(touched_ips)).all():
            pipeline.apply_to_alert(a, pipeline.assess_alert(db, a, with_explanation=False))
        db.commit()

    for a in created:
        db.refresh(a)

    return IngestResponse(
        format=fmt, source=req.source,
        received=len(records), ingested=len(created),
        duplicates=duplicates, skipped=skipped,
        alerts=[AlertResponse.model_validate(a) for a in created],
        summary=summary, warnings=warnings,
    )
