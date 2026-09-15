"""
feed_ingestor.py – Multi-source, multi-format threat-feed ingestion.

Every feed arrives in its own dialect.  This module detects the format,
parses it, and normalises each record into ONE canonical shape:

    {
      "timestamp":      datetime,
      "source_ip":      str,
      "destination_ip": str | None,
      "event_type":     canonical event type (see mitre_mapper),
      "severity":       LOW | MEDIUM | HIGH | CRITICAL,
      "hostname":       str | None,      # resolved to asset_id later
      "description":    str | None,
      "raw_log":        str,             # the original line, verbatim
      "source":         feed name (SIEM, Firewall, IDS/IPS, EDR, …),
      "feed_format":    cef | syslog | json | csv | stix,
    }

Supported formats
  cef     – ArcSight Common Event Format (firewalls, WAFs, proxies)
  syslog  – RFC 3164/5424 lines incl. Suricata/Snort fast-log and key=value
  json    – JSON array, single object or NDJSON (SIEM / EDR exports)
  csv     – header row + rows (EDR / vulnerability-scanner exports)
  stix    – STIX 2.1 bundle of indicators (threat-intel feeds → IOC table)

The STIX path updates the IOC table rather than creating alerts, because a
threat-intel feed describes *indicators*, not *events*.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Iterable, Optional

from services.mitre_mapper import normalise_event_type

SUPPORTED_FORMATS = ("auto", "cef", "syslog", "json", "csv", "stix")

# ── Field-name aliases seen across SIEM / EDR / firewall exports ─────────────
_SRC_KEYS   = ("source_ip", "src_ip", "src", "sourceaddress", "source", "attacker_ip",
               "client_ip", "remote_ip", "srcip", "ip", "s_ip", "source_address")
_DST_KEYS   = ("destination_ip", "dst_ip", "dst", "destinationaddress", "target_ip",
               "dest", "dest_ip", "dstip", "victim_ip", "d_ip", "destination_address")
_EVENT_KEYS = ("event_type", "event", "signature", "rule_name", "rule", "name", "alert",
               "category", "threat_name", "detection", "msg", "message", "title")
_SEV_KEYS   = ("severity", "sev", "priority", "level", "risk", "threat_level")
_TIME_KEYS  = ("timestamp", "@timestamp", "time", "ts", "event_time", "rt", "datetime",
               "date", "detected_at", "created")
_HOST_KEYS  = ("hostname", "host", "dhost", "asset", "device", "computer", "endpoint",
               "target_host", "destination_host")
_DESC_KEYS  = ("description", "desc", "details", "summary", "message", "msg", "reason")
_FEED_KEYS  = ("log_source", "feed", "sensor", "product", "tool", "vendor", "source")

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_ARROW = re.compile(r"(?P<src>(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\s*-+>\s*(?P<dst>(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?")
_KV = re.compile(r'(\w[\w.\-]*)=("[^"]*"|\'[^\']*\'|\S+)')
_SYSLOG_TS = re.compile(r"^(?:<\d+>)?(?:\d\s)?([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_ISO_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
# Suricata / Snort fast-log: 09/15/2026-09:15:33.120451
_FASTLOG_TS = re.compile(r"^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2})(?:\.\d+)?")
_SNORT_PRIORITY = re.compile(r"\[Priority:\s*(\d)\]", re.IGNORECASE)
_SNORT_CLASS = re.compile(r"\[Classification:\s*([^\]]+)\]", re.IGNORECASE)
_SNORT_MSG = re.compile(r"\[\d+:\d+:\d+\]\s*(.+?)\s*(?:\[\*\*\]|\[Classification|\[Priority|\{)", re.IGNORECASE)


class FeedParseError(ValueError):
    """Raised when a payload cannot be parsed in the requested format."""


# ── Helpers ──────────────────────────────────────────────────────────────────

def _first(d: dict, keys: Iterable[str]) -> Optional[str]:
    lowered = {str(k).lower(): v for k, v in d.items()}
    for k in keys:
        v = lowered.get(k.lower())
        if v in (None, "") or isinstance(v, (dict, list)):
            continue
        return str(v).strip().strip('"').strip("'")
    return None


def _to_severity(value: Optional[str]) -> str:
    """Map numeric, word or vendor-specific severities onto our four levels."""
    if value is None:
        return "MEDIUM"
    v = str(value).strip().upper()
    if v in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return v
    words = {
        "INFO": "LOW", "INFORMATIONAL": "LOW", "NOTICE": "LOW", "MINOR": "LOW", "DEBUG": "LOW",
        "WARN": "MEDIUM", "WARNING": "MEDIUM", "MODERATE": "MEDIUM", "MED": "MEDIUM",
        "MAJOR": "HIGH", "ERROR": "HIGH", "SEVERE": "HIGH", "IMPORTANT": "HIGH",
        "CRIT": "CRITICAL", "EMERGENCY": "CRITICAL", "EMERG": "CRITICAL", "FATAL": "CRITICAL",
        "VERY HIGH": "CRITICAL", "VERY-HIGH": "CRITICAL",
    }
    if v in words:
        return words[v]
    try:
        n = float(v)
    except ValueError:
        return "MEDIUM"
    # Numeric scale assumed 0-10 (CEF); Snort priorities are handled by the
    # syslog parser before reaching here.
    if n >= 9:
        return "CRITICAL"
    if n >= 7:
        return "HIGH"
    if n >= 4:
        return "MEDIUM"
    return "LOW"


def _snort_priority_to_severity(p: int) -> str:
    return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}.get(p, "LOW")


def _parse_timestamp(value: Optional[str]) -> datetime:
    """Best-effort timestamp parsing; unknown → now (UTC, naive)."""
    now = datetime.utcnow()
    if not value:
        return now
    v = str(value).strip()
    # epoch seconds / millis
    if re.fullmatch(r"\d{10}(\.\d+)?", v):
        return datetime.fromtimestamp(float(v), tz=timezone.utc).replace(tzinfo=None)
    if re.fullmatch(r"\d{13}", v):
        return datetime.fromtimestamp(int(v) / 1000, tz=timezone.utc).replace(tzinfo=None)
    # ISO 8601
    try:
        iso = v.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt
    except ValueError:
        pass
    # syslog "Sep 15 12:00:01" carries no year → assume the current year
    try:
        return datetime.strptime(f"{now.year} {v}", "%Y %b %d %H:%M:%S")
    except ValueError:
        pass
    for fmt in ("%b %d %Y %H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%m/%d/%Y-%H:%M:%S"):
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            continue
    return now


def _canonical(
    *, raw: str, feed_format: str, source_ip: Optional[str], destination_ip: Optional[str],
    event_type: Optional[str], severity: Optional[str], timestamp: Optional[str],
    hostname: Optional[str], description: Optional[str], source: Optional[str],
    default_source: str,
) -> Optional[dict]:
    if not source_ip:
        # A record with no source indicator cannot be correlated — skip it.
        return None
    return {
        "timestamp":      _parse_timestamp(timestamp),
        "source_ip":      source_ip,
        "destination_ip": destination_ip,
        "event_type":     normalise_event_type(event_type),
        "raw_event_type": event_type,
        "severity":       _to_severity(severity),
        "hostname":       hostname,
        "description":    description,
        "raw_log":        raw.strip(),
        "source":         source or default_source,
        "feed_format":    feed_format,
    }


# ── CEF ──────────────────────────────────────────────────────────────────────

def _split_cef_header(line: str) -> list[str]:
    """Split the 7 pipe-delimited CEF header fields, honouring '\\|' escapes."""
    parts, buf, i = [], [], 0
    while i < len(line) and len(parts) < 7:
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            buf.append(line[i + 1]); i += 2; continue
        if ch == "|":
            parts.append("".join(buf)); buf = []; i += 1; continue
        buf.append(ch); i += 1
    parts.append(line[i:] if len(parts) == 7 else "".join(buf))
    return parts


def parse_cef(text: str, default_source: str = "Firewall") -> list[dict]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        idx = line.find("CEF:")
        if idx < 0:
            continue
        body = line[idx:]
        parts = _split_cef_header(body)
        if len(parts) < 8:
            continue
        _, vendor, product, _version, sig_id, name, sev, ext = parts[:8]
        kv = {k: v.strip('"') for k, v in _KV.findall(ext)}
        # syslog prefix (before "CEF:") may carry the timestamp
        prefix_ts = None
        m = _SYSLOG_TS.match(line[:idx]) if idx else None
        if m:
            prefix_ts = m.group(1)
        rec = _canonical(
            raw=line, feed_format="cef",
            source_ip=kv.get("src") or kv.get("sourceAddress"),
            destination_ip=kv.get("dst") or kv.get("destinationAddress"),
            event_type=name or kv.get("cat") or sig_id,
            severity=sev,
            timestamp=kv.get("rt") or kv.get("end") or kv.get("start") or prefix_ts,
            hostname=kv.get("dhost") or kv.get("destinationHostName"),
            description=kv.get("msg") or f"{vendor} {product}: {name}",
            source=_vendor_to_source(vendor, product) or default_source,
            default_source=default_source,
        )
        if rec:
            rec["cef"] = {"vendor": vendor, "product": product, "signature_id": sig_id}
            records.append(rec)
    return records


def _vendor_to_source(vendor: str, product: str) -> Optional[str]:
    text = f"{vendor} {product}".lower()
    if any(k in text for k in ("firewall", "asa", "fortigate", "palo", "pan-os", "checkpoint", "fw")):
        return "Firewall"
    if any(k in text for k in ("suricata", "snort", "ids", "ips", "zeek", "bro")):
        return "IDS/IPS"
    if any(k in text for k in ("crowdstrike", "falcon", "sentinel", "defender", "edr", "carbon", "cortex")):
        return "EDR"
    if any(k in text for k in ("proofpoint", "mimecast", "mail", "smtp", "email")):
        return "Email Security"
    if any(k in text for k in ("splunk", "qradar", "siem", "elastic", "sentinel one")):
        return "SIEM"
    if any(k in text for k in ("nessus", "qualys", "vuln", "openvas")):
        return "Vulnerability Scanner"
    return None


# ── Syslog / Suricata / Snort / key=value ─────────────────────────────────────

def parse_syslog(text: str, default_source: str = "IDS/IPS") -> list[dict]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        kv = {k.lower(): v.strip('"\'') for k, v in _KV.findall(line)}
        src = dst = None
        m = _ARROW.search(line)
        if m:
            src, dst = m.group("src"), m.group("dst")
        src = src or _first(kv, _SRC_KEYS)
        dst = dst or _first(kv, _DST_KEYS)
        if not src:
            ips = _IPV4.findall(line)
            # skip leading host-ip in syslog header by preferring later matches
            if ips:
                src = ips[0] if len(ips) == 1 else ips[-2]
                dst = dst or (ips[-1] if len(ips) > 1 else None)

        # Event name: Snort/Suricata fast-log signature, else kv, else free text
        event = None
        sm = _SNORT_MSG.search(line)
        if sm:
            event = sm.group(1)
        if not event:
            event = _first(kv, _EVENT_KEYS)
        if not event:
            cm = _SNORT_CLASS.search(line)
            if cm:
                event = cm.group(1)
        if not event:
            # free-text after the process tag "name[pid]:"
            tail = re.split(r"\]:\s*|:\s+", line, maxsplit=1)
            event = tail[1] if len(tail) > 1 else line

        # Severity
        sev = None
        pm = _SNORT_PRIORITY.search(line)
        if pm:
            sev = _snort_priority_to_severity(int(pm.group(1)))
        if not sev:
            sev = _first(kv, _SEV_KEYS)

        # Timestamp
        ts = _first(kv, _TIME_KEYS)
        if not ts:
            im = _ISO_TS.search(line)
            if im:
                ts = im.group(0)
        if not ts:
            fm = _FASTLOG_TS.match(line)
            if fm:
                ts = fm.group(1)
        if not ts:
            hm = _SYSLOG_TS.match(line)
            if hm:
                ts = hm.group(1)

        # Originating sensor name (e.g. "suricata[1234]:")
        source = _first(kv, _FEED_KEYS)
        if not source:
            pm2 = re.search(r"\s([a-zA-Z][\w\-]*)\[\d+\]:", line)
            if pm2:
                source = _vendor_to_source(pm2.group(1), "") or default_source

        rec = _canonical(
            raw=line, feed_format="syslog",
            source_ip=src, destination_ip=dst, event_type=event, severity=sev,
            timestamp=ts, hostname=_first(kv, _HOST_KEYS),
            description=_first(kv, ("msg", "message", "description")) or event,
            source=source, default_source=default_source,
        )
        if rec:
            records.append(rec)
    return records


# ── JSON / NDJSON ─────────────────────────────────────────────────────────────

def _load_json_objects(text: str) -> list[dict]:
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON – one object per line
        objs = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise FeedParseError(f"Invalid JSON line: {line[:80]}…") from exc
        return objs
    if isinstance(data, dict):
        # common envelopes
        for key in ("alerts", "events", "results", "data", "hits", "records"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    raise FeedParseError("JSON payload must be an object, an array or NDJSON")


def _record_from_mapping(obj: dict, raw: str, feed_format: str, default_source: str) -> Optional[dict]:
    # Flatten one level of nesting ({"source": {"ip": ...}} style exports)
    flat = dict(obj)
    for k, v in obj.items():
        if isinstance(v, dict):
            for k2, v2 in v.items():
                flat.setdefault(f"{k}_{k2}", v2)
                flat.setdefault(f"{k}.{k2}", v2)
    src = _first(flat, _SRC_KEYS) or _first(flat, ("source_ip", "source.ip", "src_ip", "source_address"))
    if src and not _IPV4.fullmatch(src):
        # "source" may be the feed name rather than an IP — look deeper
        src = _first(flat, ("source_ip", "source.ip", "src_ip", "src", "attacker_ip", "client_ip"))
    return _canonical(
        raw=raw, feed_format=feed_format,
        source_ip=src,
        destination_ip=_first(flat, _DST_KEYS) or _first(flat, ("destination.ip", "dest.ip")),
        event_type=_first(flat, _EVENT_KEYS),
        severity=_first(flat, _SEV_KEYS),
        timestamp=_first(flat, _TIME_KEYS),
        hostname=_first(flat, _HOST_KEYS) or _first(flat, ("host.name", "destination.hostname")),
        description=_first(flat, _DESC_KEYS),
        source=(lambda s: s if s and not _IPV4.fullmatch(s) else None)(_first(flat, _FEED_KEYS)),
        default_source=default_source,
    )


def parse_json(text: str, default_source: str = "SIEM") -> list[dict]:
    records = []
    for obj in _load_json_objects(text):
        if not isinstance(obj, dict):
            continue
        rec = _record_from_mapping(obj, json.dumps(obj, separators=(",", ":")), "json", default_source)
        if rec:
            records.append(rec)
    return records


# ── CSV ──────────────────────────────────────────────────────────────────────

def parse_csv(text: str, default_source: str = "EDR") -> list[dict]:
    text = text.strip()
    if not text:
        return []
    try:
        dialect = csv.Sniffer().sniff(text.splitlines()[0], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    records = []
    for row in reader:
        row = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
        raw = ",".join(row.values())
        rec = _record_from_mapping(row, raw, "csv", default_source)
        if rec:
            records.append(rec)
    return records


# ── STIX 2.1 (indicators → IOC table) ────────────────────────────────────────

_STIX_PATTERN = re.compile(
    r"\[\s*(?P<type>ipv4-addr|ipv6-addr|domain-name|url|file):"
    r"(?P<prop>value|hashes\.'?(?:SHA-256|SHA-1|MD5)'?)\s*=\s*'(?P<val>[^']+)'\s*\]",
    re.IGNORECASE,
)


def parse_stix(text: str) -> list[dict]:
    """
    Return IOC dicts {ioc_value, ioc_type, reputation, confidence, threat_type,
    first_seen, last_seen} from a STIX 2.1 bundle (or bare indicator list).
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FeedParseError("STIX payload is not valid JSON") from exc
    objects = data.get("objects", []) if isinstance(data, dict) else data
    if not isinstance(objects, list):
        raise FeedParseError("STIX bundle must contain an 'objects' array")

    # malware objects give us a threat_type name to attach via relationships
    names = {o.get("id"): o.get("name") for o in objects if isinstance(o, dict) and o.get("type") in ("malware", "campaign", "intrusion-set", "threat-actor")}
    rel_threat = {}
    for o in objects:
        if isinstance(o, dict) and o.get("type") == "relationship" and o.get("relationship_type") == "indicates":
            rel_threat[o.get("source_ref")] = names.get(o.get("target_ref"))

    iocs = []
    for o in objects:
        if not isinstance(o, dict) or o.get("type") != "indicator":
            continue
        m = _STIX_PATTERN.search(o.get("pattern", ""))
        if not m:
            continue
        stype = m.group("type").lower()
        ioc_type = {"ipv4-addr": "IP", "ipv6-addr": "IP", "domain-name": "DOMAIN", "url": "URL", "file": "HASH"}[stype]
        labels = [str(x).lower() for x in (o.get("labels") or o.get("indicator_types") or [])]
        confidence = float(o.get("confidence", 50))
        # reputation: malicious-activity label pushes high; anomalous-activity moderate
        if any("malicious" in l for l in labels):
            reputation = max(80.0, confidence)
        elif any("anomalous" in l or "suspicious" in l for l in labels):
            reputation = max(50.0, confidence * 0.8)
        else:
            reputation = confidence * 0.7
        threat_type = rel_threat.get(o.get("id")) or _threat_type_from_text(
            " ".join([o.get("name", ""), o.get("description", ""), " ".join(labels)])
        )
        iocs.append({
            "ioc_value":   m.group("val"),
            "ioc_type":    ioc_type,
            "reputation":  round(min(reputation, 100.0), 1),
            "confidence":  round(min(confidence, 100.0), 1),
            "threat_type": threat_type,
            "first_seen":  _parse_timestamp(o.get("valid_from") or o.get("created")),
            "last_seen":   _parse_timestamp(o.get("modified") or o.get("created")),
            "stix_id":     o.get("id"),
            "name":        o.get("name"),
        })
    return iocs


def _threat_type_from_text(text: str) -> Optional[str]:
    et = normalise_event_type(text)
    return None if et == "Unknown" else et


# ── Format detection + dispatch ───────────────────────────────────────────────

def detect_format(text: str) -> str:
    t = text.lstrip()
    if not t:
        raise FeedParseError("Empty payload")
    first = t.splitlines()[0]
    if "CEF:" in first[:200]:
        return "cef"
    if t[0] in "{[":
        low = t[:4000].lower()
        if '"type": "bundle"' in low or '"type":"bundle"' in low or '"type": "indicator"' in low \
                or '"type":"indicator"' in low or '"pattern"' in low:
            return "stix"
        return "json"
    # CSV: header row with commas/semicolons and at least one known column
    header_cells = [c.strip().lower() for c in re.split(r"[,;\t|]", first)]
    known = set(_SRC_KEYS) | set(_EVENT_KEYS) | set(_TIME_KEYS) | set(_SEV_KEYS)
    if len(header_cells) >= 3 and any(c in known for c in header_cells):
        return "csv"
    return "syslog"


def parse(text: str, fmt: str = "auto", default_source: Optional[str] = None) -> tuple[str, list[dict]]:
    """
    Parse `text` in `fmt` (or auto-detect).  Returns (format, records) where
    records are alert dicts for event feeds and IOC dicts for STIX.
    """
    fmt = (fmt or "auto").lower()
    if fmt not in SUPPORTED_FORMATS:
        raise FeedParseError(f"Unsupported format '{fmt}'. Use one of {SUPPORTED_FORMATS}.")
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt == "cef":
        return fmt, parse_cef(text, default_source or "Firewall")
    if fmt == "syslog":
        return fmt, parse_syslog(text, default_source or "IDS/IPS")
    if fmt == "json":
        return fmt, parse_json(text, default_source or "SIEM")
    if fmt == "csv":
        return fmt, parse_csv(text, default_source or "EDR")
    if fmt == "stix":
        return fmt, parse_stix(text)
    raise FeedParseError(f"Unsupported format '{fmt}'")
