# Problem Statement — Challenge D2: Threat Intelligence Correlation & Alert Prioritisation

## The situation

A defence Security Operations Centre is fed by many independent systems at once:

| Source | Typical format | Typical volume |
|---|---|---|
| SIEM (QRadar, Splunk, Elastic) | JSON / NDJSON exports, nested fields | thousands / day |
| Perimeter firewalls, WAF, proxies | CEF (ArcSight Common Event Format) | thousands / day |
| Network IDS/IPS (Suricata, Snort, Zeek) | syslog, fast-log signatures | hundreds–thousands / day |
| Endpoint detection & response | CSV / JSON exports | hundreds / day |
| Threat-intelligence sharing | STIX 2.1 indicator bundles | daily updates |
| Satellite / sensor telemetry, human reports | free text | tens / day |

Every source has its own field names, severity scale, timestamp convention and event vocabulary.
`"ET MALWARE Cobalt Strike Beacon Observed"`, `"Outbound C2 beacon to known malicious host"` and
`{"rule_name": "Command and control traffic"}` are the same behaviour described three ways.

## Why it hurts

* **Nobody can read it all.** A four-person analyst team cannot triage 5 000 alerts a shift.
  Industry surveys consistently report the majority of alerts go uninvestigated.
* **Asymmetric cost of errors.** A missed genuine intrusion against a domain controller is
  catastrophic; a wasted hour on a port scan from a scanner node is merely expensive. Both errors
  come from the same root cause — no reliable way to tell them apart quickly.
* **Correlation is manual.** The most dangerous activity is rarely one loud alert; it is five
  medium alerts from one actor progressing through the kill chain across three feeds. Spotting
  that by hand means holding five consoles in your head.
* **Commanders need answers, not queues.** A commander asks "what do I need to act on right now,
  and why?" The answer must be structured BLUF — bottom line first, supporting detail after — and
  it must arrive in minutes, not after a shift-long analysis.

## Why existing tooling falls short

* SIEM correlation rules are brittle, vendor-specific and silent about *why* they fired.
* Severity as reported by the source is not priority: a `HIGH` from an IDS on a test laptop is
  less urgent than a `MEDIUM` from an EDR on a domain controller.
* Threat-intel platforms enrich indicators but do not turn enrichment into a decision.
* None of them produce commander-grade output; an analyst still has to write the brief.

## What a solution must do (the challenge, restated as acceptance criteria)

1. **Ingest multi-source feeds** in their native formats without a bespoke connector per source.
2. **Correlate** alerts across actors, assets and time and **separate genuine threats from false
   positives** — explainably, and improving as analysts give feedback.
3. **Map attacker techniques to MITRE ATT&CK** so activity is described in a shared vocabulary and
   multi-stage progressions become visible.
4. **Generate prioritised BLUF investigation summaries** a commander can read in minutes.

ThreatNexus is built against exactly these four criteria — see
[solution-overview.md](solution-overview.md).
