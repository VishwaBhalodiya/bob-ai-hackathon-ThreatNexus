"""
seed.py – Populate ThreatNexus database with realistic sample data.
Run once:  python seed.py
"""
import sys
import os

# Make sure imports resolve from backend/
sys.path.insert(0, os.path.dirname(__file__))

from datetime import datetime, timedelta
import random

from database import SessionLocal, ensure_schema
import models
from services import risk_engine, threat_intelligence, ai_engine, pipeline

ensure_schema()

db = SessionLocal()

# ── Clear existing data ───────────────────────────────────────────────────────
db.query(models.Recommendation).delete()
db.query(models.ThreatEvent).delete()
db.query(models.Alert).delete()
db.query(models.IOC).delete()
db.query(models.Asset).delete()
db.commit()

# ── Assets (6–8, mix of criticality) ─────────────────────────────────────────
assets_data = [
    # hostname,            ip_address,       asset_type,           criticality,  department
    ("DC01.corp.local",    "10.0.0.10",      "Domain Controller",  "CRITICAL",   "IT Infrastructure"),
    ("SQLSRV01.corp",      "10.0.0.20",      "Database Server",    "HIGH",       "Data Engineering"),
    ("WEB01.corp",         "10.0.1.10",      "Web Server",         "HIGH",       "Engineering"),
    ("FILESVR01.corp",     "10.0.0.30",      "File Server",        "MEDIUM",     "IT Operations"),
    ("HR-LAPTOP-12",       "192.168.1.45",   "Laptop",             "LOW",        "Human Resources"),
    ("FIN-WS-08",          "192.168.1.82",   "Workstation",        "MEDIUM",     "Finance"),
    ("DEV-MACBOOK-07",     "192.168.2.14",   "Laptop",             "LOW",        "Engineering"),
    ("BACKUP-SRV02.corp",  "10.0.0.40",      "Backup Server",      "HIGH",       "IT Operations"),
]

assets = []
for hostname, ip, atype, crit, dept in assets_data:
    a = models.Asset(
        hostname=hostname, ip_address=ip, asset_type=atype,
        criticality=crit, department=dept
    )
    db.add(a)
    assets.append(a)

db.commit()
for a in assets:
    db.refresh(a)

# ── IOCs (8–10, mix of reputation) ───────────────────────────────────────────
now = datetime.utcnow()
iocs_data = [
    # ioc_value,            ioc_type, reputation, confidence, threat_type
    ("185.220.101.47",      "IP",     95,  92, "Command & Control"),
    ("91.92.109.173",       "IP",     88,  85, "Ransomware"),
    ("malware-c2.ru",       "DOMAIN", 97,  95, "Command & Control"),
    ("phish-bank.tk",       "DOMAIN", 82,  78, "Phishing"),
    ("5f2b3c9a1d8e4f7c",   "HASH",   91,  89, "Malware Execution"),
    ("104.21.55.200",       "IP",     45,  55, "Port Scan"),
    ("198.51.100.22",       "IP",     15,  30, None),
    ("203.0.113.99",        "IP",     72,  80, "Brute Force"),
    ("update-patch.info",   "DOMAIN", 60,  65, "Phishing"),
    ("2a02:6b8::2:242",     "IP",     30,  40, None),
    # Attack-chain actor — fixed timestamps so lookup_ioc matches exactly
    ("45.155.204.18",       "IP",     96,  94, "Command & Control"),
]

iocs = []
for val, itype, rep, conf, ttype in iocs_data:
    i = models.IOC(
        ioc_value=val, ioc_type=itype, reputation=rep,
        confidence=conf, threat_type=ttype,
        first_seen=now - timedelta(days=random.randint(10, 180)),
        last_seen=now - timedelta(hours=random.randint(1, 48)),
    )
    db.add(i)
    iocs.append(i)

# Fix timestamps for the attack-chain IOC (last entry) to meet spec exactly
iocs[-1].first_seen = now - timedelta(days=45)
iocs[-1].last_seen  = now - timedelta(hours=2)

db.commit()
for i in iocs:
    db.refresh(i)

# ── Source lookup (event_type → originating feed/tool) ───────────────────────
EVENT_SOURCE = {
    "Port Scan":            "IDS/IPS",
    "SQL Injection":        "IDS/IPS",
    "Brute Force":          "SIEM",
    "Suspicious Login":     "SIEM",
    "Lateral Movement":     "SIEM",
    "Malware Execution":    "EDR",
    "Ransomware":           "EDR",
    "Privilege Escalation": "EDR",
    "Credential Dumping":   "EDR",
    "Command & Control":    "Firewall",
    "Data Exfiltration":    "Firewall",
    "Phishing":             "Email Security",
}


# ── Alerts (15–20) ────────────────────────────────────────────────────────────
# (source_ip, dest_ip, event_type, severity, asset_idx)
alerts_spec = [
    ("185.220.101.47",  "10.0.0.10",   "Command & Control",    "CRITICAL", 0),  # DC
    ("185.220.101.47",  "10.0.0.10",   "Lateral Movement",     "HIGH",     0),  # DC (same attacker)
    ("91.92.109.173",   "10.0.0.20",   "Ransomware",           "CRITICAL", 1),  # DB Server
    ("91.92.109.173",   "10.0.0.30",   "Ransomware",           "HIGH",     3),  # File Server
    ("203.0.113.99",    "10.0.0.10",   "Brute Force",          "HIGH",     0),  # DC
    ("203.0.113.99",    "192.168.1.82","Brute Force",          "MEDIUM",   5),  # Finance WS
    ("104.21.55.200",   "10.0.1.10",   "Port Scan",            "MEDIUM",   2),  # Web Server
    ("104.21.55.200",   "10.0.0.20",   "Port Scan",            "LOW",      1),  # DB Server
    ("198.51.100.22",   "192.168.1.45","Suspicious Login",     "LOW",      4),  # HR Laptop
    ("185.220.101.47",  "10.0.0.40",   "Data Exfiltration",    "CRITICAL", 7),  # Backup Server
    ("91.92.109.173",   "192.168.2.14","Malware Execution",    "HIGH",     6),  # Dev Laptop
    ("203.0.113.99",    "10.0.1.10",   "SQL Injection",        "HIGH",     2),  # Web Server
    ("198.51.100.22",   "192.168.1.82","Phishing",             "MEDIUM",   5),  # Finance WS
    ("185.220.101.47",  "10.0.0.20",   "Credential Dumping",   "CRITICAL", 1),  # DB Server
    ("104.21.55.200",   "192.168.1.45","Phishing",             "LOW",      4),  # HR Laptop
    ("91.92.109.173",   "10.0.0.10",   "Privilege Escalation", "CRITICAL", 0),  # DC
    ("203.0.113.99",    "10.0.0.40",   "Port Scan",            "MEDIUM",   7),  # Backup Server
    ("198.51.100.22",   "192.168.2.14","Suspicious Login",     "LOW",      6),  # Dev Laptop
]

statuses = ["OPEN", "OPEN", "OPEN", "IN_PROGRESS", "RESOLVED"]

created_alerts = []
for idx, (src, dst, etype, sev, asset_idx) in enumerate(alerts_spec):
    asset = assets[asset_idx]

    # Enrichment
    ioc_data = threat_intelligence.lookup_ioc(db, src)

    # Use a pre-committed db for correlation (no circular dependency)
    corr_score = 0.0  # seed pass – no prior alerts yet; will be realistic once live

    # Risk
    risk_result = risk_engine.calculate_risk(
        severity=sev,
        ioc_reputation=ioc_data["reputation"],
        asset_criticality=asset.criticality,
        event_type=etype,
        correlation_score=corr_score,
    )

    alert = models.Alert(
        timestamp=now - timedelta(hours=random.randint(0, 72)),
        source_ip=src,
        destination_ip=dst,
        event_type=etype,
        severity=sev,
        asset_id=asset.id,
        status=random.choice(statuses),
        risk_score=risk_result["risk_score"],
        priority=risk_result["priority"],
        source=EVENT_SOURCE.get(etype, "SIEM"),
    )
    db.add(alert)
    created_alerts.append((alert, ioc_data, risk_result, asset))

db.commit()
for alert, _, _, _ in created_alerts:
    db.refresh(alert)

# ── ThreatEvents + Recommendations ───────────────────────────────────────────
for alert, ioc_data, risk_result, asset in created_alerts:
    # ThreatEvent
    ioc_id = ioc_data.get("ioc_id")
    te = models.ThreatEvent(
        alert_id=alert.id,
        ioc_id=ioc_id,
        event_type=alert.event_type,
        description=(
            f"{alert.event_type} detected from {alert.source_ip} "
            f"targeting {asset.hostname}. "
            + (f"IOC identified as {ioc_data['threat_type']}." if ioc_data.get("threat_type") else "")
        ),
        timestamp=alert.timestamp,
    )
    db.add(te)

    # AI recommendation
    alert_data_payload = {
        "source_ip": alert.source_ip,
        "event_type": alert.event_type,
        "priority": risk_result["priority"],
        "risk_score": risk_result["risk_score"],
        "severity": alert.severity,
        "asset_hostname": asset.hostname,
        "asset_criticality": asset.criticality,
        "ioc_reputation": ioc_data["reputation"],
        "threat_type": ioc_data.get("threat_type"),
        "correlation_score": 0.0,
    }
    rec_text = ai_engine.generate_recommendation(alert_data_payload)
    rec = models.Recommendation(
        alert_id=alert.id,
        recommendation=rec_text,
        generated_by="ai_engine",
    )
    db.add(rec)

db.commit()

# ── Attack-chain sequence (5 alerts, fixed 2-minute cadence) ─────────────────
# Source: 45.155.204.18  →  DC01.corp.local (assets[0])
# Timestamps are anchored to `now` so all 5 fall within the 10-minute
# correlation window (base_time to base_time + 8 min).
# Tactics: Initial Access → Credential Access → Privilege Escalation
#          → Execution → Command & Control  (5 distinct tactics ≥ 3 → chain)
CHAIN_SRC  = "45.155.204.18"
CHAIN_DST  = "10.0.0.10"        # DC01
CHAIN_ASSET = assets[0]          # DC01.corp.local, CRITICAL

chain_spec = [
    # (event_type,             severity,   minutes_offset)
    ("Phishing",            "MEDIUM",   0),
    ("Brute Force",         "HIGH",     2),
    ("Privilege Escalation","HIGH",     4),
    ("Malware Execution",   "CRITICAL", 6),
    ("Command & Control",   "CRITICAL", 8),
]

base_time = now - timedelta(minutes=14)   # whole chain sits 14–22 min ago

chain_ioc_data = threat_intelligence.lookup_ioc(db, CHAIN_SRC)

chain_alerts = []
for etype, sev, offset in chain_spec:
    risk_result = risk_engine.calculate_risk(
        severity=sev,
        ioc_reputation=chain_ioc_data["reputation"],
        asset_criticality=CHAIN_ASSET.criticality,
        event_type=etype,
        correlation_score=0.0,
    )
    alert = models.Alert(
        timestamp=base_time + timedelta(minutes=offset),
        source_ip=CHAIN_SRC,
        destination_ip=CHAIN_DST,
        event_type=etype,
        severity=sev,
        asset_id=CHAIN_ASSET.id,
        status="OPEN",
        risk_score=risk_result["risk_score"],
        priority=risk_result["priority"],
        source=EVENT_SOURCE.get(etype, "SIEM"),
    )
    db.add(alert)
    chain_alerts.append((alert, chain_ioc_data, risk_result, CHAIN_ASSET))

db.commit()
for alert, _, _, _ in chain_alerts:
    db.refresh(alert)

# ThreatEvents + Recommendations for chain alerts (same logic as main loop)
for alert, ioc_data, risk_result, asset in chain_alerts:
    ioc_id = ioc_data.get("ioc_id")
    te = models.ThreatEvent(
        alert_id=alert.id,
        ioc_id=ioc_id,
        event_type=alert.event_type,
        description=(
            f"{alert.event_type} detected from {alert.source_ip} "
            f"targeting {asset.hostname}. "
            + (f"IOC identified as {ioc_data['threat_type']}." if ioc_data.get("threat_type") else "")
        ),
        timestamp=alert.timestamp,
    )
    db.add(te)

    alert_data_payload = {
        "source_ip": alert.source_ip,
        "event_type": alert.event_type,
        "priority": risk_result["priority"],
        "risk_score": risk_result["risk_score"],
        "severity": alert.severity,
        "asset_hostname": asset.hostname,
        "asset_criticality": asset.criticality,
        "ioc_reputation": ioc_data["reputation"],
        "threat_type": ioc_data.get("threat_type"),
        "correlation_score": 0.0,
    }
    rec_text = ai_engine.generate_recommendation(alert_data_payload)
    rec = models.Recommendation(
        alert_id=alert.id,
        recommendation=rec_text,
        generated_by="ai_engine",
    )
    db.add(rec)

db.commit()

# ── Retroactive raw_log population (4 alerts) ────────────────────────────────
# Each log line is realistic for its source type and contains at least one
# IOC value matching a seeded IOC so extract-iocs can demonstrate a real hit.
#
# Index mapping (created_alerts, 0-based):
#   0  = C2  on DC        (185.220.101.47)  → Firewall log
#   2  = Ransomware on DB (91.92.109.173)   → EDR log
#   4  = Brute Force on DC (203.0.113.99)   → SIEM/Windows event log
#   12 = Phishing Finance WS (198.51.100.22)→ Email Security log
raw_log_overrides = [
    (0, (
        "ALLOW TCP 185.220.101.47:4444 -> 10.0.0.10:443 BYTES=18240 "
        "POLICY=outbound-c2-detect ACTION=alert RULE=99 "
        "http://malware-c2.ru/beacon?id=dc01&stage=2"
    ), "Firewall detected outbound beacon to known C2 node; high-volume encrypted channel."),

    (2, (
        "EDR ALERT host=SQLSRV01 pid=4812 proc=svchost.exe "
        "action=ransom_drop file=C:\\Users\\Public\\DECRYPT_ME.txt "
        "contacted=91.92.109.173 hash=5f2b3c9a1d8e4f7c"
        "abcd1234abcd1234abcd1234abcd12345f2b3c9a1d8e4f7cabcd1234abcd1234"
    ), "EDR detected ransomware dropper; contacted C2 and wrote ransom note."),

    (4, (
        "WinEvt 4625 AUDIT_FAILURE host=DC01.corp.local "
        "src_ip=203.0.113.99 target_account=Administrator "
        "logon_type=3 failures=47 domain=corp.local"
    ), "Active Directory brute force — 47 failed logons against Administrator from single external IP."),

    (12, (
        "SMTP BLOCK from=noreply@phish-bank.tk to=j.harris@corp.local "
        "subject='Urgent: Verify your account' src_ip=198.51.100.22 "
        "url=http://update-patch.info/verify?token=8f3a disposition=QUARANTINE"
    ), "Email security gateway quarantined credential-phishing lure with embedded redirect URL."),
]

for idx, raw_log_text, desc_text in raw_log_overrides:
    alert_obj = created_alerts[idx][0]
    alert_obj.raw_log = raw_log_text
    alert_obj.description = desc_text

db.commit()

chain_ids = [a.id for a, _, _, _ in chain_alerts]
total_alerts = len(created_alerts) + len(chain_alerts)

# ── Final pass: correlation, verdicts, MITRE mapping ─────────────────────────
# Every alert above was scored with correlation_score=0 because its siblings
# did not exist yet.  Now that the whole picture is in the DB, run the real
# pipeline so stored risk/priority/verdict/MITRE fields match what the API
# would compute live.

# ── Retroactive analyst feedback (5 alerts) ───────────────────────────────────
# created_alerts indices (0-based): 0=C2 on DC, 2=Ransomware on DB,
#   4=Brute Force on DC, 7=Port Scan on DB, 14=Phishing on HR Laptop
feedback_overrides = [
    (0,  "TRUE_POSITIVE"),   # CRITICAL C2 → confirmed
    (2,  "TRUE_POSITIVE"),   # CRITICAL Ransomware → confirmed
    (4,  "ESCALATED"),       # HIGH Brute Force on DC → escalated
    (7,  "FALSE_POSITIVE"),  # LOW Port Scan on DB Server → noise
    (14, "FALSE_POSITIVE"),  # LOW Phishing on HR Laptop (104.21.55.200) → noise
]

for idx, fb_value in feedback_overrides:
    alert_obj = created_alerts[idx][0]
    alert_obj.feedback = fb_value
    alert_obj.feedback_at = now - timedelta(hours=random.randint(1, 6))

db.commit()

rescore = pipeline.rescore_all(db)

print(f"[OK] Seeded {len(assets)} assets, {len(iocs)} IOCs, {total_alerts} alerts.")
print(f"[OK] Pipeline pass: {rescore['rescored']} alerts scored, verdicts + MITRE mapping stored.")
print(f"[OK] Attack chain seeded: alerts {chain_ids[0]}-{chain_ids[-1]} on {CHAIN_SRC} -> {CHAIN_ASSET.hostname}")
print(f"[OK] Feedback set on {len(feedback_overrides)} alerts.")
print("     Run: uvicorn main:app --reload")
