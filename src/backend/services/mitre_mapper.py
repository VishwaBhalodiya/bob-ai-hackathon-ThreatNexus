# MITRE ATT&CK mapper – the single source of truth for event_type → technique.
#
# ai_engine.py, correlation_engine.py and the ingest normaliser all import
# from here so the mapping can never drift between layers.  The frontend
# reads the mapped values straight off the API (mitre_* fields on alerts).

from typing import Optional

# Kill-chain order used for timelines, coverage strips and chain detection.
TACTIC_ORDER: list[str] = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
]

# event_type → (technique_id, technique_name, tactic)
_MITRE: dict[str, tuple[str, str, str]] = {
    "Port Scan":            ("T1046", "Network Service Discovery",              "Discovery"),
    "Suspicious Login":     ("T1078", "Valid Accounts",                         "Defense Evasion"),
    "Phishing":             ("T1566", "Phishing",                               "Initial Access"),
    "SQL Injection":        ("T1190", "Exploit Public-Facing Application",      "Initial Access"),
    "Brute Force":          ("T1110", "Brute Force",                            "Credential Access"),
    "Credential Dumping":   ("T1003", "OS Credential Dumping",                  "Credential Access"),
    "Lateral Movement":     ("T1021", "Remote Services",                        "Lateral Movement"),
    "Privilege Escalation": ("T1068", "Exploitation for Privilege Escalation",  "Privilege Escalation"),
    "Command & Control":    ("T1071", "Application Layer Protocol",             "Command & Control"),
    "Malware Execution":    ("T1204", "User Execution",                         "Execution"),
    "Data Exfiltration":    ("T1041", "Exfiltration Over C2 Channel",           "Exfiltration"),
    "Ransomware":           ("T1486", "Data Encrypted for Impact",              "Impact"),
    "DDoS":                 ("T1498", "Network Denial of Service",              "Impact"),
    "Persistence":          ("T1547", "Boot or Logon Autostart Execution",      "Persistence"),
    "Web Shell":            ("T1505.003", "Server Software Component: Web Shell", "Persistence"),
    "DNS Tunneling":        ("T1071.004", "Application Layer Protocol: DNS",    "Command & Control"),
    "Reconnaissance":       ("T1595", "Active Scanning",                        "Reconnaissance"),
}

# Free-text aliases seen in raw feeds → canonical event_type.  Lower-cased,
# matched as substrings so "ssh brute-force attempt" → "Brute Force".
_ALIASES: list[tuple[str, str]] = [
    ("ransom",               "Ransomware"),
    ("encrypt",              "Ransomware"),
    ("exfil",                "Data Exfiltration"),
    ("data transfer",        "Data Exfiltration"),
    ("beacon",               "Command & Control"),
    ("c2",                   "Command & Control"),
    ("command and control",  "Command & Control"),
    ("command & control",    "Command & Control"),
    ("dns tunnel",           "DNS Tunneling"),
    ("brute",                "Brute Force"),
    ("password spray",       "Brute Force"),
    ("4625",                 "Brute Force"),          # Windows failed logon
    ("mimikatz",             "Credential Dumping"),
    ("lsass",                "Credential Dumping"),
    ("credential dump",      "Credential Dumping"),
    ("lateral",              "Lateral Movement"),
    ("psexec",               "Lateral Movement"),
    ("smb",                  "Lateral Movement"),
    ("privilege",            "Privilege Escalation"),
    ("privesc",              "Privilege Escalation"),
    ("malware",              "Malware Execution"),
    ("trojan",               "Malware Execution"),
    ("dropper",              "Malware Execution"),
    ("sqli",                 "SQL Injection"),
    ("sql injection",        "SQL Injection"),
    ("union select",         "SQL Injection"),
    ("phish",                "Phishing"),
    ("spearphish",           "Phishing"),
    ("web shell",            "Web Shell"),
    ("webshell",             "Web Shell"),
    ("port scan",            "Port Scan"),
    ("portscan",             "Port Scan"),
    ("nmap",                 "Port Scan"),
    ("scan",                 "Port Scan"),
    ("ddos",                 "DDoS"),
    ("flood",                "DDoS"),
    ("persistence",          "Persistence"),
    ("scheduled task",       "Persistence"),
    ("registry run",         "Persistence"),
    ("impossible travel",    "Suspicious Login"),
    ("suspicious login",     "Suspicious Login"),
    ("anomalous login",      "Suspicious Login"),
    ("logon",                "Suspicious Login"),
    ("recon",                "Reconnaissance"),
]


def map_event(event_type: Optional[str]) -> Optional[dict]:
    """
    Return {"technique_id", "technique", "tactic", "url"} for a canonical
    event_type, or None when the event type has no mapping.
    """
    if not event_type:
        return None
    hit = _MITRE.get(event_type)
    if not hit:
        return None
    tid, name, tactic = hit
    return {
        "technique_id": tid,
        "technique":    name,
        "tactic":       tactic,
        "url":          f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }


def tactic_for(event_type: Optional[str]) -> Optional[str]:
    """Shorthand: just the tactic name (used by the correlation engine)."""
    hit = _MITRE.get(event_type or "")
    return hit[2] if hit else None


def normalise_event_type(raw: Optional[str]) -> str:
    """
    Coerce a free-text event name from any feed into one of the canonical
    event types.  Exact (case-insensitive) matches win; otherwise the first
    alias substring that appears in the text.  Falls back to "Unknown".
    """
    if not raw:
        return "Unknown"
    text = raw.strip()
    for canon in _MITRE:
        if canon.lower() == text.lower():
            return canon
    lowered = text.lower()
    for needle, canon in _ALIASES:
        if needle in lowered:
            return canon
    return "Unknown"


def all_techniques() -> list[dict]:
    """Every mapping as a list (for the /api/mitre endpoints)."""
    return [
        {"event_type": et, **map_event(et)}
        for et in _MITRE
    ]
