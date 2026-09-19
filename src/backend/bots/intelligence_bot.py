# Bot 2 — Intelligence Bot
#
# Handles intelligence-domain data sources:
#   - Threat intelligence reports (structured + unstructured)
#   - OSINT feeds
#   - IOC (indicator-of-compromise) feeds
#   - Historical incident data
#   - Cyber intelligence reports
#
# For each input the bot:
#   1. Extracts all indicators (IPs, domains, hashes, URLs, entities)
#   2. Identifies threat behaviours described in free text
#   3. Maps extracted behaviour to MITRE ATT&CK techniques
#   4. Produces a normalised IntelligenceEvent with a confidence score
#
# MITRE specifically describes using threat intelligence reports and raw
# incident data to identify adversary techniques — this is the natural
# home for ATT&CK mapping from unstructured prose.

import re
from datetime import datetime
from typing import Optional

from services.ioc_extractor import extract_iocs
from services.mitre_mapper import normalise_event_type, map_event, _MITRE

# ── Behaviour keyword extraction ──────────────────────────────────────────────
# We scan free-text threat-report prose for these patterns and map them to
# canonical event types, exactly as the MITRE ATT&CK mapping layer does for
# structured events.  Order matters — more specific patterns win.

_BEHAVIOUR_PATTERNS: list[tuple[str, str]] = [
    (r"credential.{0,20}(dump|theft|steal)",      "Credential Dumping"),
    (r"(lsass|mimikatz|procdump)",                 "Credential Dumping"),
    (r"(lateral.movement|psexec|pass.the.hash)",   "Lateral Movement"),
    (r"(powershell|encoded.command|base64.payload)","Malware Execution"),
    (r"(c2|command.and.control|command.&.control|beacon)", "Command & Control"),
    (r"(exfiltrat|data.transfer|data.theft)",       "Data Exfiltration"),
    (r"(ransom|encrypt.files)",                     "Ransomware"),
    (r"(brute.forc|password.spray|failed.logon)",   "Brute Force"),
    (r"(phish|credential.harvest)",                 "Phishing"),
    (r"(privilege.escalat|privesc|uac.bypass)",     "Privilege Escalation"),
    (r"(persistence|scheduled.task|registry.run)",  "Persistence"),
    (r"(port.scan|portscan|nmap|recon)",            "Reconnaissance"),
    (r"(sql.inject|union.select|sqli)",             "SQL Injection"),
    (r"(web.shell|webshell)",                       "Web Shell"),
    (r"(dns.tunnel)",                               "DNS Tunneling"),
    (r"(ddos|flood|denial.of.service)",             "DDoS"),
]

# These entity patterns mark important names / hostnames in prose
_ENTITY_PATTERN = re.compile(
    r"\b([A-Z][A-Z0-9\-]{2,15}(?:\.[A-Z][A-Z0-9\-]+)*)\b"  # ALL-CAPS hostnames
)


def _extract_behaviours(text: str) -> list[str]:
    """Extract canonical event types from free-text prose."""
    lowered = text.lower()
    found: list[str] = []
    seen: set[str] = set()
    for pattern, event_type in _BEHAVIOUR_PATTERNS:
        if event_type not in seen and re.search(pattern, lowered):
            found.append(event_type)
            seen.add(event_type)
    return found


def _extract_entities(text: str) -> list[str]:
    """Extract named entities (hostnames, asset IDs) from text."""
    return list(dict.fromkeys(_ENTITY_PATTERN.findall(text)))[:10]


def _intel_confidence(
    report_confidence: Optional[float],
    ioc_count: int,
    behaviour_count: int,
    mitre_count: int,
) -> float:
    """
    Estimate intelligence confidence (0.0-1.0) from report metadata and
    what was successfully extracted.
    """
    base = report_confidence if report_confidence is not None else 0.5
    extraction_bonus = min(ioc_count * 0.03 + behaviour_count * 0.05 + mitre_count * 0.04, 0.25)
    return round(min(base + extraction_bonus, 1.0), 3)


# ── Public API ─────────────────────────────────────────────────────────────────

def process_report(raw_report: dict) -> dict:
    """
    Accept a raw intelligence input (structured or unstructured) and return a
    normalised IntelligenceEvent dict.

    Input fields (all optional):
        source, timestamp, title, body, confidence, severity,
        indicators (list), techniques (list), report_id, tlp

    Output shape:
        {
            "bot":              "INTEL_BOT",
            "event_id":         str,               # INT-<timestamp-hash>
            "source":           str,               # THREAT_INTEL | OSINT | THREAT_FEED
            "timestamp":        datetime,
            "report_id":        str | None,
            "title":            str | None,
            "indicators":       list[dict],        # extracted IOC objects
            "entities":         list[str],         # hostnames, asset IDs
            "behaviours":       list[str],         # canonical event types
            "mitre_techniques": list[dict],        # [{technique_id, technique, tactic, url}]
            "confidence":       float,             # 0.0-1.0
            "severity":         str,               # LOW | MEDIUM | HIGH | CRITICAL
            "raw":              dict,
        }
    """
    source    = (raw_report.get("source") or "THREAT_INTEL").upper()
    report_id = raw_report.get("report_id")
    title     = raw_report.get("title") or ""
    body      = raw_report.get("body") or raw_report.get("description") or ""
    full_text = f"{title} {body}"
    severity  = (raw_report.get("severity") or "MEDIUM").upper()
    conf_raw  = raw_report.get("confidence")

    ts_raw = raw_report.get("timestamp")
    if isinstance(ts_raw, datetime):
        ts = ts_raw
    elif ts_raw:
        try:
            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ts = datetime.utcnow()
    else:
        ts = datetime.utcnow()

    # Extract all IOCs from the full text
    iocs = extract_iocs(full_text)
    # Also honour pre-supplied indicator lists (e.g. from threat feeds)
    prebuilt: list[str] = raw_report.get("indicators") or []
    seen_vals = {i["value"].lower() for i in iocs}
    for val in prebuilt:
        if val.lower() not in seen_vals:
            # Guess type: IP or domain
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", val):
                iocs.append({"type": "IP", "value": val})
            else:
                iocs.append({"type": "DOMAIN", "value": val})
            seen_vals.add(val.lower())

    # Extract behaviours and entities from prose
    behaviours = _extract_behaviours(full_text)
    if not behaviours:
        # Fallback: try the normaliser on the title
        et = normalise_event_type(title)
        if et != "Unknown":
            behaviours = [et]

    entities = _extract_entities(full_text)

    # Map every identified behaviour to MITRE ATT&CK
    mitre_techniques: list[dict] = []
    seen_ids: set[str] = set()
    # Also honour pre-supplied technique IDs (e.g. "T1110")
    for t in (raw_report.get("techniques") or []):
        # Reverse-look technique ID → existing mapping if possible
        for et, (tid, name, tactic) in _MITRE.items():
            if tid == t and tid not in seen_ids:
                mitre_techniques.append(map_event(et))
                seen_ids.add(tid)
    for behaviour in behaviours:
        mapped = map_event(behaviour)
        if mapped and mapped["technique_id"] not in seen_ids:
            mitre_techniques.append(mapped)
            seen_ids.add(mapped["technique_id"])

    confidence = _intel_confidence(conf_raw, len(iocs), len(behaviours), len(mitre_techniques))

    ts_str = ts.strftime("%Y%m%d%H%M%S")
    event_id = f"INT-{ts_str}-{abs(hash(source + full_text[:40])) % 100000:05d}"

    return {
        "bot":              "INTEL_BOT",
        "event_id":         event_id,
        "source":           source,
        "timestamp":        ts,
        "report_id":        report_id,
        "title":            title or None,
        "indicators":       iocs,
        "entities":         entities,
        "behaviours":       behaviours,
        "mitre_techniques": mitre_techniques,
        "confidence":       confidence,
        "severity":         severity,
        "raw":              raw_report,
    }


def process_batch(reports: list[dict]) -> list[dict]:
    """Process a list of raw intelligence inputs."""
    return [process_report(r) for r in reports]


def extract_ioc_reputation_hints(intel_events: list[dict]) -> dict[str, float]:
    """
    From a list of processed IntelligenceEvents, build a dict mapping
    indicator value → maximum observed confidence.  Used by the Fusion Bot
    to apply intel weighting to correlation.
    """
    hints: dict[str, float] = {}
    for ev in intel_events:
        for ioc in ev.get("indicators", []):
            val = ioc.get("value", "").lower()
            if val:
                hints[val] = max(hints.get(val, 0.0), ev["confidence"])
    return hints
