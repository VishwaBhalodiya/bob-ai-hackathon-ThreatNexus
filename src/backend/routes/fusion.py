"""
routes/fusion.py — Multi-source Bot Fusion API

POST /api/fusion/run          Run the full 4-bot pipeline over supplied events
POST /api/fusion/cyber        Process events through Bot 1 (Cyber/SIEM Bot)
POST /api/fusion/intelligence Process inputs through Bot 2 (Intelligence Bot)
POST /api/fusion/satellite    Process telemetry through Bot 3 (Satellite Bot)
GET  /api/fusion/samples      Return sample inputs for each bot (for demo)
GET  /api/fusion/weights      Get current fusion risk-score weights
PUT  /api/fusion/weights      Update fusion weights (admin/config)
"""
import json
import os
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from bots import cyber_bot, intelligence_bot, satellite_bot, fusion_bot
from services import ai_engine

router = APIRouter(prefix="/api/fusion", tags=["fusion"])

_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

# ── In-memory state store for the live demo ───────────────────────────────────
# Stores the most-recently processed bot outputs so the dashboard can show
# "live" bot feeds and the fusion result.
_live_state: dict[str, Any] = {
    "cyber":     [],
    "intel":     [],
    "satellite": [],
    "fusion":    None,
    "updated_at": None,
}

# Fusion weights are mutable via PUT /api/fusion/weights
_current_weights: dict[str, float] = fusion_bot.get_default_weights()


# ── Pydantic models ────────────────────────────────────────────────────────────

class CyberIngestRequest(BaseModel):
    events: list[dict]

class IntelIngestRequest(BaseModel):
    reports: list[dict]

class SatelliteIngestRequest(BaseModel):
    telemetry: list[dict]

class FusionRunRequest(BaseModel):
    """
    Supply events for all three source bots.
    The Fusion Bot then runs automatically over their outputs.
    """
    cyber_events:    list[dict] = []
    intel_reports:   list[dict] = []
    satellite_data:  list[dict] = []
    asset_criticality: str = "LOW"

class WeightsUpdateRequest(BaseModel):
    cyber_evidence:       Optional[float] = None
    intel_corroboration:  Optional[float] = None
    satellite_evidence:   Optional[float] = None
    historical_behaviour: Optional[float] = None
    cross_source_corr:    Optional[float] = None
    asset_criticality:    Optional[float] = None
    recency:              Optional[float] = None


def _dt_serialise(obj: Any) -> Any:
    """JSON-serialise datetimes inside nested structures."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _dt_serialise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_dt_serialise(i) for i in obj]
    return obj


# ── Sample data ───────────────────────────────────────────────────────────────

def _load_sample(path: str) -> list | dict:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError:
        return []


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/weights")
def get_weights():
    """Return the current fusion risk-score weights."""
    return {
        "weights": _current_weights,
        "description": {
            "cyber_evidence":       "Weight for cyber sensor/SIEM evidence (0-1)",
            "intel_corroboration":  "Weight for intelligence report corroboration (0-1)",
            "satellite_evidence":   "Weight for satellite/telemetry anomaly evidence (0-1)",
            "historical_behaviour": "Weight for historical incident patterns (0-1)",
            "cross_source_corr":    "Weight for cross-source time coincidence (0-1)",
            "asset_criticality":    "Weight for target asset criticality (0-1)",
            "recency":              "Weight for recency of events (0-1)",
        },
    }


@router.put("/weights")
def update_weights(req: WeightsUpdateRequest):
    """
    Update fusion weights.  Missing fields are left unchanged.
    Weights should sum to ≤1.0; the system clips individual scores at 100.
    """
    update = req.model_dump(exclude_none=True)
    _current_weights.update(update)
    return {"weights": _current_weights, "updated": list(update.keys())}


@router.post("/cyber")
def process_cyber(req: CyberIngestRequest):
    """
    Run Bot 1 (Cyber/SIEM Bot) over the supplied events.
    Returns normalised CyberEvent objects.
    """
    results = cyber_bot.process_batch(req.events)
    _live_state["cyber"] = results
    _live_state["updated_at"] = datetime.utcnow().isoformat()
    return {
        "bot":        "CYBER_BOT",
        "processed":  len(results),
        "events":     _dt_serialise(results),
    }


@router.post("/intelligence")
def process_intel(req: IntelIngestRequest):
    """
    Run Bot 2 (Intelligence Bot) over the supplied reports.
    Returns normalised IntelligenceEvent objects.
    """
    results = intelligence_bot.process_batch(req.reports)
    _live_state["intel"] = results
    _live_state["updated_at"] = datetime.utcnow().isoformat()
    return {
        "bot":        "INTEL_BOT",
        "processed":  len(results),
        "events":     _dt_serialise(results),
    }


@router.post("/satellite")
def process_satellite(req: SatelliteIngestRequest):
    """
    Run Bot 3 (Satellite/Telemetry Bot) over the supplied telemetry.
    Returns normalised SatelliteEvent objects (anomalous and non-anomalous).
    """
    results = satellite_bot.process_batch(req.telemetry)
    _live_state["satellite"] = results
    _live_state["updated_at"] = datetime.utcnow().isoformat()
    return {
        "bot":        "SATELLITE_BOT",
        "processed":  len(results),
        "anomalous":  sum(1 for e in results if e.get("is_anomalous")),
        "events":     _dt_serialise(results),
    }


@router.post("/run")
def run_fusion(req: FusionRunRequest):
    """
    Run the full 4-bot pipeline:
      1. Bot 1 processes cyber_events
      2. Bot 2 processes intel_reports
      3. Bot 3 processes satellite_data
      4. Bot 4 (Fusion Bot) correlates all three outputs

    Returns the complete FusionResult including:
    - Evidence Matrix (which sources contributed)
    - Cross-source correlation confidence
    - Multi-source risk score + breakdown
    - False-positive probability + label
    - MITRE ATT&CK technique consensus
    - BLUF summary (via IBM Bob or template fallback)
    """
    if not req.cyber_events and not req.intel_reports and not req.satellite_data:
        raise HTTPException(
            status_code=422,
            detail="Supply at least one source stream (cyber_events, intel_reports, or satellite_data)"
        )

    # Step 1-3: run each source bot
    cyber_out = cyber_bot.process_batch(req.cyber_events)
    intel_out = intelligence_bot.process_batch(req.intel_reports)
    sat_out   = satellite_bot.process_batch(req.satellite_data)

    # Step 4: Fusion Bot
    result = fusion_bot.fuse(
        cyber_events      = cyber_out,
        intel_events      = intel_out,
        sat_events        = sat_out,
        asset_criticality = req.asset_criticality,
        weights           = _current_weights,
    )

    # Generate BLUF from the fusion result
    bluf = ai_engine.generate_explanation(result["bluf_data"], allow_llm=True)

    # Persist to live state for the dashboard
    _live_state["cyber"]     = cyber_out
    _live_state["intel"]     = intel_out
    _live_state["satellite"] = sat_out
    _live_state["fusion"]    = result
    _live_state["updated_at"] = datetime.utcnow().isoformat()

    return _dt_serialise({
        "bot":                    "FUSION_BOT",
        "timestamp":              result["timestamp"],
        "sources_present":        result["sources_present"],
        "correlation_confidence": result["correlation_confidence"],
        "evidence_matrix":        result["evidence_matrix"],
        "risk":                   result["risk"],
        "fp":                     result["fp"],
        "mitre_techniques":       result["mitre_techniques"],
        "bluf":                   bluf,
        "bot_outputs": {
            "cyber":     [
                {k: v for k, v in e.items() if k != "raw"} for e in cyber_out
            ],
            "intel":     [
                {k: v for k, v in e.items() if k != "raw"} for e in intel_out
            ],
            "satellite": [
                {k: v for k, v in e.items() if k != "raw"} for e in sat_out
            ],
        },
    })


@router.get("/live")
def get_live_state():
    """
    Return the most-recently processed bot outputs and fusion result.
    Used by the dashboard for the live-demo panel.
    """
    if not _live_state["updated_at"]:
        return {"message": "No fusion has been run yet. POST to /api/fusion/run first.", "state": None}
    return _dt_serialise({
        "updated_at":  _live_state["updated_at"],
        "bot_counts": {
            "cyber":     len(_live_state["cyber"]),
            "intel":     len(_live_state["intel"]),
            "satellite": len(_live_state["satellite"]),
        },
        "fusion": {
            "sources_present":        _live_state["fusion"]["sources_present"]        if _live_state["fusion"] else None,
            "correlation_confidence": _live_state["fusion"]["correlation_confidence"] if _live_state["fusion"] else None,
            "risk_score":             _live_state["fusion"]["risk"]["risk_score"]     if _live_state["fusion"] else None,
            "priority":               _live_state["fusion"]["risk"]["priority"]       if _live_state["fusion"] else None,
            "fp_label":               _live_state["fusion"]["fp"]["fp_label"]         if _live_state["fusion"] else None,
            "evidence_matrix":        _live_state["fusion"]["evidence_matrix"]        if _live_state["fusion"] else None,
        } if _live_state["fusion"] else None,
    })


@router.get("/samples")
def get_samples():
    """
    Return realistic sample inputs for each bot so the UI can run a live demo
    with one click — the same way the existing ingest panel shows sample feeds.
    """
    return {
        "description": "Sample data for each bot. POST these to /api/fusion/run to see the full pipeline in action.",
        "demo_request": {
            "cyber_events": _load_sample(os.path.join(_DATA_DIR, "cyber", "endpoint_events.json"))
                          + _load_sample(os.path.join(_DATA_DIR, "cyber", "siem_events.json")),
            "intel_reports": _load_sample(os.path.join(_DATA_DIR, "intelligence", "threat_reports.json")),
            "satellite_data": _load_sample(os.path.join(_DATA_DIR, "satellite", "telemetry.json")),
            "asset_criticality": "CRITICAL",
        },
        "bots": {
            "cyber_bot": {
                "name": "Bot 1 — Cyber/SIEM Bot",
                "description": "Handles SIEM, EDR, network sensor, firewall and authentication log data",
                "sample": _load_sample(os.path.join(_DATA_DIR, "cyber", "endpoint_events.json"))[:1],
            },
            "intel_bot": {
                "name": "Bot 2 — Intelligence Bot",
                "description": "Processes threat-intelligence reports, OSINT and IOC feeds",
                "sample": _load_sample(os.path.join(_DATA_DIR, "intelligence", "threat_reports.json"))[:1],
            },
            "satellite_bot": {
                "name": "Bot 3 — Satellite/Telemetry Bot",
                "description": "Monitors satellite telemetry for anomalies and communication degradation",
                "sample": _load_sample(os.path.join(_DATA_DIR, "satellite", "telemetry.json"))[:1],
            },
        },
    }
