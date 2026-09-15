"""End-to-end API tests: ingest → correlate → verdict → MITRE → BLUF brief."""

CEF = (
    "CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Outbound C2 beacon|9|"
    "rt=2026-09-15T09:12:41Z src=185.220.101.47 dst=10.0.0.10 dhost=DC01.corp.local msg=beacon\n"
    "CEF:0|Cisco|ASA|9.16|106023|Deny inbound connection|2|"
    "rt=2026-09-15T09:31:07Z src=8.8.8.8 dst=192.168.1.45 dhost=HR-LAPTOP-12 msg=blocked\n"
)

CHAIN_JSON = [
    {"timestamp": "2026-09-15T09:00:00Z", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.10", "event": "phishing", "severity": "medium"},
    {"timestamp": "2026-09-15T09:02:00Z", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.10", "event": "brute force", "severity": "high"},
    {"timestamp": "2026-09-15T09:04:00Z", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.10", "event": "privilege escalation", "severity": "high"},
    {"timestamp": "2026-09-15T09:06:00Z", "src_ip": "185.220.101.47", "dst_ip": "10.0.0.10", "event": "c2 beacon", "severity": "critical"},
]


def test_health(client):
    assert client.get("/").json()["status"] == "ok"


def test_ingest_cef_creates_alerts_with_verdicts_and_mitre(client):
    r = client.post("/api/ingest", json={"payload": CEF, "format": "auto"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["format"] == "cef"
    assert body["received"] == 2 and body["ingested"] == 2
    by_ip = {a["source_ip"]: a for a in body["alerts"]}

    c2 = by_ip["185.220.101.47"]
    assert c2["asset_id"] is not None                 # linked to DC01 by dst IP
    assert c2["event_type"] == "Command & Control"
    assert c2["mitre_technique_id"] == "T1071"
    assert c2["verdict"] == "GENUINE_THREAT"
    assert c2["priority"] in ("HIGH", "CRITICAL")
    assert c2["feed_format"] == "cef"

    noise = by_ip["8.8.8.8"]
    assert noise["event_type"] == "Unknown"
    assert noise["verdict"] == "LIKELY_FALSE_POSITIVE"
    assert any("Could not map" in w for w in body["warnings"])


def test_ingest_is_idempotent(client):
    first = client.post("/api/ingest", json={"payload": CEF, "format": "cef"}).json()
    second = client.post("/api/ingest", json={"payload": CEF, "format": "cef"}).json()
    assert first["ingested"] == 2
    assert second["ingested"] == 0 and second["duplicates"] == 2


def test_ingest_bad_payload_422(client):
    r = client.post("/api/ingest", json={"payload": "{oops", "format": "json"})
    assert r.status_code == 422


def test_attack_chain_detection_and_brief(client):
    r = client.post("/api/ingest", json={"payload": CHAIN_JSON, "format": "json", "source": "SIEM"})
    assert r.status_code == 200, r.text
    ids = [a["id"] for a in r.json()["alerts"]]

    # The last alert in the chain sees the earlier three in its ±10 min window
    detail = client.get(f"/api/alerts/{ids[-1]}").json()
    assert detail["is_attack_chain"] is True
    assert len(detail["related_events"]) == 3
    assert detail["verdict_detail"]["verdict"] == "GENUINE_THREAT"
    assert detail["mitre"]["tactic"] == "Command & Control"
    bluf = detail["ai_explanation"]
    assert set(bluf) == {"bottom_line", "situation", "assessment", "recommendation"}
    assert bluf["bottom_line"].startswith(detail["priority"])

    chains = client.get("/api/attack-chains?window_hours=720").json()["chains"]
    assert chains and chains[0]["is_multi_stage"] is True
    assert chains[0]["tactics"][0] == "Initial Access"

    brief = client.get("/api/brief?window_hours=720&limit=5").json()
    assert brief["posture"] in ("CRITICAL", "ELEVATED")
    assert brief["bottom_line"].startswith(brief["posture"])
    assert brief["attack_chains"][0]["source_ip"] == "185.220.101.47"
    assert brief["priorities"][0]["rank"] == 1
    assert brief["priorities"][0]["bluf"]["bottom_line"]
    assert all(p["verdict"] != "LIKELY_FALSE_POSITIVE" for p in brief["priorities"])


def test_feedback_updates_verdict_and_learns(client):
    r = client.post("/api/ingest", json={"payload": CEF, "format": "cef"}).json()
    c2 = next(a for a in r["alerts"] if a["source_ip"] == "185.220.101.47")

    fb = client.patch(f"/api/alerts/{c2['id']}/feedback", json={"feedback": "false_positive"})
    assert fb.status_code == 200
    assert fb.json()["verdict"] == "LIKELY_FALSE_POSITIVE"
    assert fb.json()["verdict_confidence"] >= 95

    bad = client.patch(f"/api/alerts/{c2['id']}/feedback", json={"feedback": "maybe"})
    assert bad.status_code == 422

    listing = client.get("/api/alerts?verdict=LIKELY_FALSE_POSITIVE").json()
    assert any(a["id"] == c2["id"] for a in listing)


def test_stix_ingest_updates_iocs_and_rescores(client):
    # unknown IP first → not genuine
    r = client.post("/api/ingest", json={"payload": [
        {"src_ip": "77.91.124.20", "dst_ip": "10.0.0.10", "event": "c2 beacon", "severity": "medium"}
    ], "format": "json"}).json()
    alert = r["alerts"][0]
    assert alert["verdict"] != "GENUINE_THREAT"

    bundle = {"type": "bundle", "objects": [{
        "type": "indicator", "id": "indicator--x",
        "pattern": "[ipv4-addr:value = '77.91.124.20']",
        "indicator_types": ["malicious-activity"], "confidence": 95,
    }]}
    s = client.post("/api/ingest", json={"payload": bundle, "format": "stix"}).json()
    assert s["format"] == "stix" and s["iocs_added"] == 1 and s["alerts_rescored"] == 1

    after = client.get(f"/api/alerts/{alert['id']}").json()
    assert after["verdict"] == "GENUINE_THREAT"
    assert after["ioc_info"]["reputation"] >= 80


def test_dashboard_and_mitre_coverage(client):
    client.post("/api/ingest", json={"payload": CEF, "format": "cef"})
    d = client.get("/api/dashboard").json()
    assert d["total"] == 2
    assert d["verdict_summary"]["genuine"] + d["verdict_summary"]["likely_false_positive"] + d["verdict_summary"]["needs_review"] == 2
    assert d["formats_breakdown"] == {"cef": 2}

    cov = client.get("/api/mitre/coverage").json()
    tactics = {t["tactic"]: t["count"] for t in cov["tactics"]}
    assert tactics["Command & Control"] == 1
    assert cov["techniques"][0]["technique_id"] == "T1071"


def test_analyze_endpoint(client):
    r = client.post("/api/analyze", json={"source_ip": "185.220.101.47", "event_type": "Ransomware", "asset_id": 1, "severity": "CRITICAL"})
    assert r.status_code == 200
    body = r.json()
    assert body["priority"] == "CRITICAL"
    assert body["verdict"]["verdict"] == "GENUINE_THREAT"
    assert body["mitre"]["technique_id"] == "T1486"
    assert client.get("/api/alerts").json() == []      # analyze never persists


# ── Merged from teammate design: IOC-driven scoring, CRUD, workflow, Bob status ──

def test_iocs_in_log_drive_reputation(client):
    """A low-reputation source IP whose log references a known-malicious domain
    must score on the domain, not the IP."""
    client.post("/api/iocs", json={"ioc_value": "phish-bank.tk", "ioc_type": "DOMAIN",
                                   "reputation": 82, "confidence": 78, "threat_type": "Phishing"})
    r = client.post("/api/ingest", json={"payload": [{
        "src_ip": "198.51.100.22", "dst_ip": "192.168.1.45", "event": "phishing", "severity": "medium",
        "message": "Quarantined mail from noreply@phish-bank.tk with credential-harvest link",
    }], "format": "json", "source": "Email Security"}).json()
    a = r["alerts"][0]
    values = {i["value"] for i in a["iocs"]}
    assert "phish-bank.tk" in values and "198.51.100.22" in values
    assert a["verdict"] != "LIKELY_FALSE_POSITIVE"

    detail = client.get(f"/api/alerts/{a['id']}").json()
    assert detail["risk_breakdown"]["ioc_reputation"] == 82
    assert any("phish-bank.tk" in reason for reason in detail["verdict_detail"]["reasons"])


def test_status_workflow(client):
    r = client.post("/api/ingest", json={"payload": CEF, "format": "cef"}).json()
    aid = r["alerts"][0]["id"]
    assert client.patch(f"/api/alerts/{aid}/status", json={"status": "in_progress"}).json()["status"] == "IN_PROGRESS"
    assert client.patch(f"/api/alerts/{aid}/status", json={"status": "RESOLVED"}).json()["status"] == "RESOLVED"
    assert client.patch(f"/api/alerts/{aid}/status", json={"status": "DONE"}).status_code == 422
    assert client.get("/api/alerts?status=RESOLVED").json()[0]["id"] == aid


def test_asset_crud_and_linking(client):
    r = client.post("/api/assets", json={"hostname": "WEB02.corp", "ip_address": "10.0.1.11",
                                         "asset_type": "Web Server", "criticality": "high", "department": "Eng"})
    assert r.status_code == 201 and r.json()["criticality"] == "HIGH"
    assert client.post("/api/assets", json=r.request.read() and {
        "hostname": "WEB02.corp", "ip_address": "10.0.1.11", "asset_type": "x", "criticality": "LOW", "department": "y"
    }).status_code == 409
    assert client.get("/api/assets").json()[0]["criticality"] == "CRITICAL"   # sorted by criticality

    ing = client.post("/api/ingest", json={"payload": [
        {"src_ip": "185.220.101.47", "dst_ip": "10.0.1.11", "event": "sqli", "severity": "high"}
    ], "format": "json"}).json()
    assert ing["alerts"][0]["asset_id"] == r.json()["id"]


def test_ioc_lookup(client):
    hit = client.get("/api/iocs/lookup/185.220.101.47").json()
    miss = client.get("/api/iocs/lookup/8.8.8.8").json()
    assert hit["found"] and hit["reputation"] == 95
    assert miss["found"] is False and miss["reputation"] == 0


def test_ai_status_reports_bob(client):
    st = client.get("/api/ai/status").json()
    assert st["provider"] == "IBM Bob"
    assert st["mode"] in ("bob", "template")
    assert "stats" in st
