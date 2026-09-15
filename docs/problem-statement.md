# Problem Statement

## Background

Modern organisations operate complex, multi-layered security architectures. A single enterprise environment routinely
generates alerts from dozens of security tools simultaneously: SIEM platforms, intrusion detection/prevention systems,
endpoint detection and response (EDR) agents, firewalls, cloud security posture managers, vulnerability scanners,
email security gateways, and threat-intelligence feeds. Each tool produces alerts in isolation, with no shared context.

## The Problem

Security Operations Centre (SOC) analysts receive between hundreds and thousands of security alerts every day.
The fundamental challenge is **not** detecting threats — the tools already do that.
The challenge is **deciding which alert to investigate first**.

Every minute spent investigating a low-priority false positive is a minute not spent on the ransomware operator
who has already established persistence inside the network. This triage failure is one of the leading causes
of data breaches going undetected for weeks or months.

Concretely:

- A Fortune 500 SOC receives **~10,000 alerts per day** on average (IBM Cost of a Data Breach Report, 2023).
- Analysts dismiss **~66% of all alerts** without investigation due to volume (Ponemon Institute, 2022).
- Mean time to identify a breach is **204 days** (IBM, 2023) — alert triage inefficiency is a direct contributor.

## Who is Affected

**Primary users:** Tier-1 and Tier-2 SOC analysts at mid-to-large enterprises who are responsible for
triaging the alert queue at the start of each shift. They need to decide — within seconds per alert —
whether a given event warrants deeper investigation or can be safely deferred.

**Secondary users:** Security managers and incident responders who need an accurate picture of the
organisation's current threat landscape to prioritise resources.

## Why It Matters

The cost of getting this wrong is extreme:

- **False negative (missed real threat):** Average breach cost of **$4.45 million** (IBM, 2023), plus regulatory fines and reputational damage.
- **False positive overload:** Analyst burnout, high staff turnover, and "alert fatigue" — a state where analysts stop paying
  attention because the noise-to-signal ratio is too high.
- **No correlation:** Without connecting related events, multi-stage attacks (initial access → lateral movement → data exfiltration)
  are invisible as individual alerts, each appearing benign in isolation.

## Why Existing Solutions Fall Short

Current SIEM platforms assign severity levels, but they are **static and context-free**: a "high" alert on a
non-critical IoT camera is treated identically to a "high" alert on the CEO's laptop or a domain controller.

Threat-intelligence platforms exist, but they require analysts to manually query each IOC — an impractical
workflow when processing hundreds of alerts per hour.

There is no unified system that **combines** threat intelligence reputation, asset criticality, behavioural
indicators, alert correlation, and AI-assisted explanation into a single, actionable ranked list.

**ThreatNexus closes this gap.**
