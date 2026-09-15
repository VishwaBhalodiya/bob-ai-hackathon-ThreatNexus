from datetime import datetime

import pytest

from services import feed_ingestor as fi


CEF_LINE = (
    "Sep 15 09:12:41 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|THREAT|Outbound C2 beacon|9|"
    "rt=2026-09-15T09:12:41Z src=185.220.101.47 dst=10.0.0.10 dhost=DC01.corp.local msg=Beacon to c2"
)
SURICATA_LINE = (
    "09/15/2026-09:15:33.120451  [**] [1:2024897:3] ET MALWARE Cobalt Strike Beacon Observed [**] "
    "[Classification: Malware Command and Control Activity Detected] [Priority: 1] {TCP} "
    "45.155.204.18:443 -> 10.0.0.10:49812"
)
KV_LINE = (
    'Sep 15 09:19:11 sensor02 sshd[8812]: src_ip=203.0.113.99 dst_ip=10.0.0.10 '
    'event="SSH brute-force: 63 failed logins" severity=high host=DC01.corp.local'
)


def test_detect_format():
    assert fi.detect_format(CEF_LINE) == "cef"
    assert fi.detect_format(SURICATA_LINE) == "syslog"
    assert fi.detect_format('{"alerts": []}') == "json"
    assert fi.detect_format('{"type": "bundle", "objects": []}') == "stix"
    assert fi.detect_format("timestamp,source_ip,event\n1,2,3") == "csv"


def test_parse_cef_extracts_fields_and_maps_event():
    fmt, recs = fi.parse(CEF_LINE, "auto")
    assert fmt == "cef" and len(recs) == 1
    r = recs[0]
    assert r["source_ip"] == "185.220.101.47"
    assert r["destination_ip"] == "10.0.0.10"
    assert r["hostname"] == "DC01.corp.local"
    assert r["event_type"] == "Command & Control"
    assert r["severity"] == "CRITICAL"          # CEF 9/10
    assert r["source"] == "Firewall"
    assert r["timestamp"] == datetime(2026, 9, 15, 9, 12, 41)
    assert r["raw_log"].startswith("Sep 15")


def test_parse_suricata_fastlog():
    fmt, recs = fi.parse(SURICATA_LINE, "syslog")
    r = recs[0]
    assert r["source_ip"] == "45.155.204.18"
    assert r["destination_ip"] == "10.0.0.10"
    assert r["event_type"] == "Command & Control"   # "Cobalt Strike Beacon" → C2 via alias
    assert r["severity"] == "CRITICAL"              # Priority: 1
    assert r["timestamp"] == datetime(2026, 9, 15, 9, 15, 33)


def test_parse_syslog_key_value():
    _, recs = fi.parse(KV_LINE, "syslog")
    r = recs[0]
    assert r["source_ip"] == "203.0.113.99"
    assert r["event_type"] == "Brute Force"
    assert r["severity"] == "HIGH"
    assert r["hostname"] == "DC01.corp.local"


def test_parse_json_nested_and_envelope():
    payload = {
        "alerts": [{
            "@timestamp": "2026-09-15T09:13:20Z",
            "rule_name": "Windows 4625 repeated failed logons",
            "severity": "high",
            "source": {"ip": "203.0.113.99"},
            "destination": {"ip": "10.0.0.10", "hostname": "DC01.corp.local"},
            "log_source": "SIEM",
        }]
    }
    import json
    _, recs = fi.parse(json.dumps(payload), "json")
    r = recs[0]
    assert r["source_ip"] == "203.0.113.99"
    assert r["destination_ip"] == "10.0.0.10"
    assert r["event_type"] == "Brute Force"
    assert r["source"] == "SIEM"           # not the nested {"ip": ...} dict


def test_parse_ndjson():
    text = '{"src_ip": "1.2.3.4", "event": "port scan", "severity": 3}\n{"src_ip": "5.6.7.8", "event": "ransomware", "severity": 10}'
    _, recs = fi.parse(text, "json")
    assert [r["event_type"] for r in recs] == ["Port Scan", "Ransomware"]
    assert [r["severity"] for r in recs] == ["LOW", "CRITICAL"]


def test_parse_csv():
    text = (
        "detected_at,hostname,source_ip,destination_ip,detection,severity\n"
        "2026-09-15 09:16:40,DC01.corp.local,91.92.109.173,10.0.0.10,Ransomware behaviour,critical\n"
    )
    fmt, recs = fi.parse(text, "auto")
    assert fmt == "csv"
    assert recs[0]["event_type"] == "Ransomware"
    assert recs[0]["severity"] == "CRITICAL"
    assert recs[0]["source"] == "EDR"


def test_parse_stix_indicators():
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "id": "indicator--1", "pattern": "[ipv4-addr:value = '77.91.124.20']",
             "indicator_types": ["malicious-activity"], "confidence": 92, "created": "2026-09-14T08:00:00Z",
             "name": "C2 server"},
            {"type": "indicator", "id": "indicator--2",
             "pattern": "[file:hashes.'SHA-256' = 'aa' ]", "confidence": 40},
            {"type": "malware", "id": "malware--1", "name": "Ransomware"},
            {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--2", "target_ref": "malware--1"},
        ],
    }
    import json
    fmt, iocs = fi.parse(json.dumps(bundle), "auto")
    assert fmt == "stix" and len(iocs) == 2
    assert iocs[0]["ioc_type"] == "IP" and iocs[0]["reputation"] >= 80
    assert iocs[0]["threat_type"] == "Command & Control"
    assert iocs[1]["ioc_type"] == "HASH" and iocs[1]["threat_type"] == "Ransomware"


def test_records_without_source_ip_are_skipped():
    _, recs = fi.parse('{"event": "port scan"}', "json")
    assert recs == []


def test_bad_format_raises():
    with pytest.raises(fi.FeedParseError):
        fi.parse("x", "yaml")
    with pytest.raises(fi.FeedParseError):
        fi.parse("{not json", "json")
