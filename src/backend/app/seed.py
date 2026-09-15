"""
Demo seed data — populates the DB with realistic assets, threat intel,
and security alerts so the platform is immediately usable after setup.
"""

from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models import Asset, ThreatIntel, Alert


def _already_seeded(db: Session) -> bool:
    return db.query(Asset).count() > 0


def seed_demo_data(db: Session):
    if _already_seeded(db):
        return

    # ── Assets ─────────────────────────────────────────────────────────────────
    assets = [
        Asset(hostname="dc01.corp.internal", ip_address="10.0.0.5",
              asset_type="server", criticality=10, owner="IT Ops",
              department="Infrastructure", tags=["domain-controller", "tier-0"]),
        Asset(hostname="dbserver02.corp.internal", ip_address="10.0.1.20",
              asset_type="server", criticality=9, owner="DBA Team",
              department="Data Engineering", tags=["database", "pii"]),
        Asset(hostname="webserver01.dmz.internal", ip_address="10.0.2.10",
              asset_type="server", criticality=7, owner="Web Team",
              department="Engineering", tags=["public-facing", "web"]),
        Asset(hostname="laptop-analyst01.corp.internal", ip_address="10.0.10.55",
              asset_type="workstation", criticality=5, owner="Alice Johnson",
              department="Security", tags=["analyst-workstation"]),
        Asset(hostname="hr-pc-007.corp.internal", ip_address="10.0.10.101",
              asset_type="workstation", criticality=6, owner="Bob Smith",
              department="HR", tags=["sensitive-data"]),
        Asset(hostname="iot-camera-lobby.corp.internal", ip_address="10.0.20.5",
              asset_type="iot", criticality=3, owner="Facilities",
              department="Facilities", tags=["iot", "camera"]),
    ]
    db.bulk_save_objects(assets)
    db.commit()

    # ── Threat Intel IOCs ──────────────────────────────────────────────────────
    now = datetime.utcnow()
    threat_intel = [
        ThreatIntel(ioc_type="ip", ioc_value="185.220.101.47",
                    reputation_score=95, threat_category="c2",
                    source="AlienVault OTX",
                    first_seen=now - timedelta(days=30), last_seen=now - timedelta(hours=2),
                    tags=["tor-exit", "c2", "apt"]),
        ThreatIntel(ioc_type="ip", ioc_value="194.165.16.73",
                    reputation_score=88, threat_category="ransomware",
                    source="VirusTotal",
                    first_seen=now - timedelta(days=15), last_seen=now - timedelta(days=1),
                    tags=["ransomware", "lockbit"]),
        ThreatIntel(ioc_type="domain", ioc_value="update-service.ru",
                    reputation_score=92, threat_category="malware",
                    source="Shodan",
                    first_seen=now - timedelta(days=60), last_seen=now - timedelta(hours=6),
                    tags=["malware-distribution", "fake-update"]),
        ThreatIntel(ioc_type="domain", ioc_value="secure-login-portal.xyz",
                    reputation_score=78, threat_category="phishing",
                    source="PhishTank",
                    first_seen=now - timedelta(days=5), last_seen=now - timedelta(hours=1),
                    tags=["phishing", "credential-theft"]),
        ThreatIntel(ioc_type="sha256",
                    ioc_value="3a4b5c6d7e8f9012345678901234567890123456789012345678901234567890ab",
                    reputation_score=99, threat_category="ransomware",
                    source="VirusTotal",
                    first_seen=now - timedelta(days=7), last_seen=now - timedelta(hours=3),
                    tags=["ransomware", "lockbit-3", "wiper"]),
        ThreatIntel(ioc_type="ip", ioc_value="91.92.240.11",
                    reputation_score=70, threat_category="scanner",
                    source="Shodan",
                    first_seen=now - timedelta(days=2), last_seen=now - timedelta(hours=12),
                    tags=["port-scanner", "mass-scan"]),
        ThreatIntel(ioc_type="url",
                    ioc_value="http://update-service.ru/payload.exe",
                    reputation_score=96, threat_category="malware",
                    source="URLhaus",
                    first_seen=now - timedelta(days=10), last_seen=now - timedelta(hours=1),
                    tags=["malware-download", "dropper"]),
        ThreatIntel(ioc_type="email", ioc_value="cfo-alert@secure-login-portal.xyz",
                    reputation_score=80, threat_category="phishing",
                    source="PhishTank",
                    first_seen=now - timedelta(days=3), last_seen=now,
                    tags=["bec", "spear-phishing"]),
    ]
    db.bulk_save_objects(threat_intel)
    db.commit()

    # ── Alerts (pre-enriched for demo) ─────────────────────────────────────────
    dc01 = db.query(Asset).filter(Asset.hostname == "dc01.corp.internal").first()
    dbsrv = db.query(Asset).filter(Asset.hostname == "dbserver02.corp.internal").first()
    web01 = db.query(Asset).filter(Asset.hostname == "webserver01.dmz.internal").first()
    hrpc = db.query(Asset).filter(Asset.hostname == "hr-pc-007.corp.internal").first()

    alerts = [
        Alert(
            title="Outbound C2 connection from Domain Controller",
            description=(
                "SIEM detected an outbound TCP/443 connection from dc01.corp.internal "
                "to known C2 server 185.220.101.47. Beacon interval ~60 s. "
                "Process: lsass.exe spawned cmd.exe which initiated the connection."
            ),
            source_system="SIEM",
            source_severity="critical",
            raw_log="2024-01-15T03:42:17Z dc01.corp.internal -> 185.220.101.47:443 ESTABLISHED pid=1234 lsass.exe",
            iocs=[{"type": "ip", "value": "185.220.101.47"}],
            asset_id=dc01.id if dc01 else None,
            risk_score=94.5,
            risk_level="CRITICAL",
            ai_explanation=(
                "This CRITICAL alert (score 94/100) indicates a likely Advanced Persistent Threat (APT) "
                "on your highest-criticality asset. The domain controller is communicating with a known "
                "Tor-exit C2 node (reputation 95/100), and process injection into lsass.exe is a classic "
                "credential-harvesting technique used by APT groups. Immediate containment is required."
            ),
            investigation_steps=[
                "Immediately isolate dc01.corp.internal from the network at the switch level.",
                "Capture a memory image (volatility) of dc01 and look for injected code in lsass.exe.",
                "Rotate all domain admin credentials and Kerberos ticket-granting ticket (krbtgt) keys.",
                "Hunt for lateral movement: review authentication logs for dc01 across all domain assets in the past 72 hours.",
            ],
            correlation_group_id="grp-apt-campaign-01",
            timestamp=now - timedelta(hours=1),
        ),
        Alert(
            title="Ransomware payload download attempt",
            description=(
                "Endpoint security detected a download attempt from http://update-service.ru/payload.exe "
                "on dbserver02.corp.internal. SHA256 matches known LockBit 3.0 variant. Download was blocked."
            ),
            source_system="Endpoint Security",
            source_severity="high",
            raw_log="2024-01-15T02:58:00Z dbserver02 HTTP GET http://update-service.ru/payload.exe BLOCKED sha256=3a4b5c6d...",
            iocs=[
                {"type": "url", "value": "http://update-service.ru/payload.exe"},
                {"type": "domain", "value": "update-service.ru"},
                {"type": "sha256", "value": "3a4b5c6d7e8f9012345678901234567890123456789012345678901234567890ab"},
            ],
            asset_id=dbsrv.id if dbsrv else None,
            risk_score=88.0,
            risk_level="CRITICAL",
            ai_explanation=(
                "A known LockBit 3.0 ransomware binary was attempted on your PII database server. "
                "Although the download was blocked, the initial vector (likely phishing or exploit) "
                "remains active and the server may already be compromised. The SHA256 hash has a "
                "99/100 reputation score. Treat as an active incident."
            ),
            investigation_steps=[
                "Verify the download was fully blocked — check proxy and EDR quarantine logs.",
                "Scan dbserver02 with an offline AV/EDR tool for persistence mechanisms.",
                "Identify how the connection was initiated — review browser history, email attachments, and scheduled tasks.",
                "Check for lateral movement from dbserver02 to other database hosts.",
            ],
            correlation_group_id="grp-apt-campaign-01",
            timestamp=now - timedelta(hours=2),
        ),
        Alert(
            title="SQL Injection probe on public web application",
            description=(
                "WAF detected 847 SQL injection probes targeting /api/users endpoint on webserver01.dmz.internal "
                "from source IP 91.92.240.11 over 15 minutes. Several probes used UNION-based extraction. "
                "Some requests returned HTTP 200 — possible data extraction."
            ),
            source_system="WAF",
            source_severity="high",
            raw_log="2024-01-15T01:15:00Z 91.92.240.11 -> webserver01 /api/users?id=1' UNION SELECT ... 200 OK",
            iocs=[{"type": "ip", "value": "91.92.240.11"}],
            asset_id=web01.id if web01 else None,
            risk_score=72.0,
            risk_level="HIGH",
            ai_explanation=(
                "This HIGH-risk alert involves 847 SQL injection probes from a known mass-scanner IP against "
                "your public-facing web server. The HTTP 200 responses on several UNION-based probes suggest "
                "the injection may have succeeded and data could have been extracted. Immediate review of "
                "application logs and database query history is required."
            ),
            investigation_steps=[
                "Pull database query logs for the 15-minute window and look for UNION SELECT statements returning data.",
                "Block 91.92.240.11 at the perimeter firewall and WAF immediately.",
                "Check application error logs for stack traces that could expose schema information.",
                "Run an integrity check on the users table and compare row counts to the last known-good backup.",
            ],
            timestamp=now - timedelta(hours=3),
        ),
        Alert(
            title="Spear-phishing email with credential-harvesting link",
            description=(
                "Email security gateway quarantined a spear-phishing email sent to bob.smith@corp.com "
                "from cfo-alert@secure-login-portal.xyz. Email subject: 'Urgent: Verify your credentials'. "
                "Contains link to http://secure-login-portal.xyz/login — known phishing domain."
            ),
            source_system="Email Security",
            source_severity="medium",
            raw_log="2024-01-15T08:30:00Z FROM:cfo-alert@secure-login-portal.xyz TO:bob.smith@corp.com QUARANTINED",
            iocs=[
                {"type": "email", "value": "cfo-alert@secure-login-portal.xyz"},
                {"type": "domain", "value": "secure-login-portal.xyz"},
            ],
            asset_id=hrpc.id if hrpc else None,
            risk_score=61.5,
            risk_level="HIGH",
            ai_explanation=(
                "A targeted spear-phishing email impersonating finance leadership was sent to an HR employee "
                "who has access to sensitive personnel data. The sending domain has a 80/100 phishing reputation "
                "and the linked page mimics a corporate login portal. Although quarantined, the attack indicates "
                "the threat actor has profiled your organisation."
            ),
            investigation_steps=[
                "Confirm the email was fully quarantined and did not reach the recipient's inbox.",
                "Check if bob.smith has logged in from any unusual location or IP in the past 24 hours.",
                "Search email gateway logs for other recipients of the same campaign.",
                "Brief HR and Finance teams on the active spear-phishing campaign targeting them.",
            ],
            timestamp=now - timedelta(hours=5),
        ),
        Alert(
            title="Unusual privileged login outside business hours",
            description=(
                "AD audit logs show that the account svc_backup logged in to dc01.corp.internal "
                "at 03:15 UTC on Saturday, which is outside normal service-account patterns. "
                "Source IP: 10.0.10.55 (analyst laptop). 14 failed attempts preceded success."
            ),
            source_system="SIEM",
            source_severity="medium",
            raw_log="2024-01-13T03:15:44Z DOMAIN\\svc_backup LOGIN SUCCESS dc01.corp.internal src=10.0.10.55 after 14 failures",
            iocs=[],
            asset_id=dc01.id if dc01 else None,
            risk_score=52.0,
            risk_level="MEDIUM",
            ai_explanation=(
                "A service account succeeded after 14 failed attempts on the domain controller outside "
                "business hours. This pattern is consistent with credential brute-force or password spray "
                "activity. The source being an analyst laptop raises the possibility of a compromised "
                "insider endpoint being used as a pivot point."
            ),
            investigation_steps=[
                "Disable svc_backup account immediately and reset its password.",
                "Review the analyst laptop (10.0.10.55) for signs of malware or remote-access tools.",
                "Audit all actions performed under svc_backup in the 30 minutes after login.",
                "Enable enhanced logging on svc_backup and similar service accounts going forward.",
            ],
            correlation_group_id="grp-apt-campaign-01",
            timestamp=now - timedelta(hours=6),
        ),
        Alert(
            title="Outbound DNS query to newly registered domain",
            description=(
                "DNS monitoring detected repeated queries for fast-update-cdn.top from "
                "multiple internal hosts. Domain registered 2 days ago, no prior reputation. "
                "NXDOMAIN responses currently but pattern consistent with DGA (domain generation algorithm)."
            ),
            source_system="Network Monitoring",
            source_severity="low",
            raw_log="2024-01-15T07:00:00Z MULTIPLE_HOSTS DNS fast-update-cdn.top NXDOMAIN",
            iocs=[{"type": "domain", "value": "fast-update-cdn.top"}],
            asset_id=None,
            risk_score=28.0,
            risk_level="LOW",
            ai_explanation=(
                "Low-risk DNS queries to a newly registered domain with no current resolution. "
                "While individually inconclusive, DGA-like patterns from multiple hosts can indicate "
                "dormant malware awaiting C2 activation. Monitor for when this domain starts resolving."
            ),
            investigation_steps=[
                "Add fast-update-cdn.top to DNS RPZ (Response Policy Zone) to block resolution.",
                "Identify all hosts querying this domain and cross-reference with other recent alerts.",
                "Monitor threat intel feeds for when this domain becomes active.",
                "Document as potential DGA indicator for the current threat campaign.",
            ],
            timestamp=now - timedelta(hours=8),
        ),
    ]

    db.bulk_save_objects(alerts)
    db.commit()
