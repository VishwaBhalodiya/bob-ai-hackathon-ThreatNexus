from services import fp_classifier as fp
from services import mitre_mapper, risk_engine


# ── MITRE mapper ─────────────────────────────────────────────────────────────

def test_map_event_known():
    m = mitre_mapper.map_event("Brute Force")
    assert m["technique_id"] == "T1110"
    assert m["tactic"] == "Credential Access"
    assert m["url"].endswith("/T1110/")


def test_map_event_unknown():
    assert mitre_mapper.map_event("Unknown") is None
    assert mitre_mapper.tactic_for("nope") is None


def test_normalise_event_type_aliases():
    assert mitre_mapper.normalise_event_type("ET MALWARE Cobalt Strike Beacon") == "Command & Control"
    assert mitre_mapper.normalise_event_type("Mimikatz-like LSASS access") == "Credential Dumping"
    assert mitre_mapper.normalise_event_type("Windows 4625 failed logons") == "Brute Force"
    assert mitre_mapper.normalise_event_type("brute force") == "Brute Force"   # case-insensitive exact
    assert mitre_mapper.normalise_event_type("Deny inbound connection") == "Unknown"
    assert mitre_mapper.normalise_event_type(None) == "Unknown"


def test_every_technique_has_tactic_in_kill_chain_order():
    for t in mitre_mapper.all_techniques():
        assert t["tactic"] in mitre_mapper.TACTIC_ORDER


# ── Risk engine ──────────────────────────────────────────────────────────────

def test_risk_score_bounds_and_priority():
    lo = risk_engine.calculate_risk("LOW", 0, "LOW", "Unknown", 0)
    hi = risk_engine.calculate_risk("CRITICAL", 100, "CRITICAL", "Ransomware", 100)
    assert 0 <= lo["risk_score"] < 30 and lo["priority"] == "LOW"
    assert hi["risk_score"] == 100 and hi["priority"] == "CRITICAL"


# ── False-positive classifier ────────────────────────────────────────────────

def test_known_malicious_ip_is_genuine():
    v = fp.classify(ioc_reputation=95, ioc_found=True, asset_criticality="CRITICAL",
                    event_type="Command & Control", severity="CRITICAL",
                    correlation_count=4, is_attack_chain=True)
    assert v["verdict"] == fp.GENUINE_THREAT
    assert v["confidence"] > 80
    assert any("known-malicious" in r for r in v["reasons"])


def test_isolated_port_scan_from_unknown_ip_is_likely_fp():
    v = fp.classify(ioc_reputation=0, ioc_found=False, asset_criticality="LOW",
                    event_type="Port Scan", severity="LOW",
                    correlation_count=0, is_attack_chain=False)
    assert v["verdict"] == fp.LIKELY_FALSE_POSITIVE
    assert any("benign noise" in r for r in v["reasons"])


def test_analyst_feedback_overrides():
    base = dict(ioc_reputation=50, ioc_found=True, asset_criticality="MEDIUM",
                event_type="Phishing", severity="MEDIUM", correlation_count=1, is_attack_chain=False)
    assert fp.classify(**base, own_feedback="FALSE_POSITIVE")["verdict"] == fp.LIKELY_FALSE_POSITIVE
    assert fp.classify(**base, own_feedback="TRUE_POSITIVE")["verdict"] == fp.GENUINE_THREAT
    assert fp.classify(**base, own_feedback="FALSE_POSITIVE")["confidence"] >= 95


def test_history_shifts_verdict():
    base = dict(ioc_reputation=30, ioc_found=True, asset_criticality="MEDIUM",
                event_type="Suspicious Login", severity="MEDIUM", correlation_count=1, is_attack_chain=False)
    neutral = fp.classify(**base)["score"]
    fp_hist = fp.classify(**base, history={"event_true_positive": 0, "event_false_positive": 3})["score"]
    tp_hist = fp.classify(**base, history={"event_true_positive": 3, "event_false_positive": 0})["score"]
    assert fp_hist < neutral < tp_hist


def test_high_reputation_never_suppressed():
    v = fp.classify(ioc_reputation=90, ioc_found=True, asset_criticality="LOW",
                    event_type="Port Scan", severity="LOW", correlation_count=0, is_attack_chain=False)
    assert v["verdict"] != fp.LIKELY_FALSE_POSITIVE
