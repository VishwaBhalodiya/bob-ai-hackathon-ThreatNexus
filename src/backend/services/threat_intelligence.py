# Threat Intelligence service – simulated enrichment against the local IOC table.
# Swap the body of `lookup_ioc` for a real VirusTotal / MISP call when ready.

from sqlalchemy.orm import Session
from models import IOC
from typing import Optional


def lookup_ioc(db: Session, ioc_value: str) -> Optional[dict]:
    """
    Look up an IOC value (IP, domain, hash, URL) in the local database.
    Returns a dict with reputation, confidence, and threat_type if found,
    or a default "unknown" result if not found.
    """
    record: Optional[IOC] = (
        db.query(IOC).filter(IOC.ioc_value == ioc_value).first()
    )

    if record:
        return {
            "found": True,
            "ioc_id": record.id,
            "ioc_value": record.ioc_value,
            "ioc_type": record.ioc_type,
            "reputation": record.reputation,
            "confidence": record.confidence,
            "threat_type": record.threat_type,
            "first_seen": record.first_seen.isoformat() if record.first_seen else None,
            "last_seen": record.last_seen.isoformat() if record.last_seen else None,
        }

    # ── Simulated enrichment for unknown IPs ─────────────────────────────────
    # In production: replace this block with a real API call, e.g.:
    #   return _call_virustotal(ioc_value)
    return {
        "found": False,
        "ioc_id": None,
        "ioc_value": ioc_value,
        "ioc_type": "IP",
        "reputation": 0.0,
        "confidence": 10.0,
        "threat_type": None,
        "first_seen": None,
        "last_seen": None,
    }


def get_ioc_reputation(db: Session, ioc_value: str) -> float:
    """Convenience helper – returns only the reputation score (0-100)."""
    result = lookup_ioc(db, ioc_value)
    return result["reputation"]
