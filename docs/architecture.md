# Architecture

## ✅ What's Built

| Component | Status | Location |
|---|---|---|
| Bot 1 — Cyber/SIEM Bot | ✅ Done | `src/backend/bots/cyber_bot.py` |
| Bot 2 — Intelligence Bot | ✅ Done | `src/backend/bots/intelligence_bot.py` |
| Bot 3 — Satellite/Telemetry Bot | ✅ Done | `src/backend/bots/satellite_bot.py` |
| Bot 4 — Fusion & Decision Bot | ✅ Done | `src/backend/bots/fusion_bot.py` |
| Evidence Matrix (cross-source) | ✅ Done | `bots/fusion_bot.py` + `components/EvidenceMatrix.jsx` |
| False-positive classifier | ✅ Done | `services/fp_classifier.py` — rule-based, analyst-feedback loop |
| Multi-source risk score (7 factors) | ✅ Done | `bots/fusion_bot.py` |
| Fusion weights API (GET/PUT) | ✅ Done | `routes/fusion.py` |
| Learning dataset (JSON schema) | ✅ Done | `data/historical/learning_dataset.json` |
| Trained ML model | ❌ Not done — dataset structure prepared for a future model |
| FusionPanel UI (Live Demo button) | ✅ Done | `src/frontend/src/components/FusionPanel.jsx` |
| Sample data files (cyber / intel / satellite) | ✅ Done | `src/backend/data/` |

---

## 4-Bot Multi-Source Intelligence Fusion

ThreatNexus is built around **four genuinely different bots** operating over **three independent
source streams**.  The key design principle, drawn from how MITRE ATT&CK itself describes
multi-source CTI: *don't have all four bots do the same thing*.  Each bot adds independent
evidence.  Bot 4 (the Fusion Bot) determines whether those independent streams **agree** — and
scores the certainty of that agreement.

```
                    ┌───────────────────────┐
                    │      LIVE SOURCES      │
                    └───────────────────────┘
                       │        │        │
             ┌─────────┘        │        └─────────┐
             ▼                  ▼                  ▼
      ┌────────────┐    ┌────────────┐    ┌────────────┐
      │   BOT 1    │    │   BOT 2    │    │   BOT 3    │
      │ CYBER/SIEM │    │   INTEL    │    │ SATELLITE  │
      │    BOT     │    │    BOT     │    │    BOT     │
      └─────┬──────┘    └─────┬──────┘    └─────┬──────┘
            │                 │                  │
            └─────────────────┼──────────────────┘
                              ▼
                    ┌──────────────────┐
                    │      BOT 4       │
                    │  FUSION &        │
                    │  DECISION BOT    │
                    └────────┬─────────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
        Evidence Matrix   FP/Risk         MITRE ATT&CK
                             │
                             ▼
                    PRIORITY + BLUF
                             │
                             ▼
                        DASHBOARD
                             │
                             ▼
                     ANALYST FEEDBACK
                             │
                             ▼
                   ┌──────────────────┐
                   │ LEARNING DATASET │
                   └────────┬─────────┘
                            │
                            ▼
                      MODEL UPDATE
```

## System diagram (full component view)

```mermaid
graph TD
    subgraph Sources["Live sources (simulated for demo)"]
        SIEM[SIEM / EDR / JSON · CSV]
        IDS[IDS / IPS · Firewall · CEF · syslog]
        TI[Threat intel · OSINT · STIX 2.1]
        SAT[Satellite telemetry · ground stations]
    end

    subgraph Bot1["Bot 1 — Cyber/SIEM Bot (bots/cyber_bot.py)"]
        C1[Normalise event]
        C2[Extract IOCs]
        C3[Cyber confidence]
        C4[MITRE candidate]
    end

    subgraph Bot2["Bot 2 — Intelligence Bot (bots/intelligence_bot.py)"]
        I1[Parse report / feed]
        I2[Extract indicators]
        I3[Behaviour extraction]
        I4[MITRE mapping]
    end

    subgraph Bot3["Bot 3 — Satellite Bot (bots/satellite_bot.py)"]
        S1[Ingest telemetry]
        S2[Compute anomaly score]
        S3[Classify anomaly type]
        S4[Evidence description]
    end

    subgraph Bot4["Bot 4 — Fusion & Decision Bot (bots/fusion_bot.py)"]
        F1[Time coincidence]
        F2[IOC overlap]
        F3[Evidence Matrix]
        F4[Multi-source risk score]
        F5[FP probability]
        F6[MITRE consensus]
        F7[BLUF data]
    end

    subgraph API["FastAPI backend (src/backend)"]
        FUS[routes/fusion.py · POST /api/fusion/run]
        ING[routes/ingest.py · POST /api/ingest]
        PIPE[services/pipeline.py · assess()]
        DB[(SQLite · alerts · iocs · assets)]
        AI[services/ai_engine.py · IBM Bob]
        BRIEF[routes/brief.py · GET /api/brief]
    end

    BOB[[IBM Bob inference API]]

    subgraph UI["React frontend (src/frontend)"]
        DASH[Dashboard · FusionPanel · FeedIngestPanel]
        EMAT[EvidenceMatrix component]
        DET[Alert Detail · BLUF · verdict · timeline]
        CB[Commander Brief · posture · chains · ranked BLUFs]
    end

    SIEM --> Bot1
    IDS  --> Bot1
    TI   --> Bot2
    SAT  --> Bot3

    Bot1 --> FUS
    Bot2 --> FUS
    Bot3 --> FUS
    FUS --> F1 --> F3
    FUS --> F2 --> F3
    F3  --> F4
    F3  --> F5
    F3  --> F6
    F3  --> F7
    F7  --> AI
    AI  -->|prompt| BOB
    BOB -->|JSON BLUF| AI

    SIEM --> ING --> PIPE --> DB
    DB --> BRIEF
    DB --> DASH
    DASH --> FUS
    DASH --> EMAT
    DET --> PIPE
    CB --> BRIEF
```

## The four bots

| Bot | Primary sources | Main responsibility |
|---|---|---|
| **Bot 1 — Cyber/SIEM Bot** | SIEM, EDR, network sensors, firewall, IDS/IPS, authentication logs | Detect and normalise cyber events; extract IOCs; assign cyber confidence; propose MITRE candidate |
| **Bot 2 — Intelligence Bot** | CTI reports, OSINT, threat feeds, IOC feeds, STIX 2.1 | Extract indicators, entities, behaviours from structured + unstructured text; map to MITRE ATT&CK |
| **Bot 3 — Satellite/Telemetry Bot** | Satellite telemetry, ground-station feeds, communication anomaly streams | Detect anomalies; score anomaly severity; produce independent evidence description for the Fusion Bot |
| **Bot 4 — Fusion & Decision Bot** | Outputs of Bots 1–3 + historical data | Correlate; compute Evidence Matrix; estimate FP likelihood; score multi-source risk; reach MITRE consensus; generate BLUF |

## Why the satellite bot does NOT say "satellite anomaly = cyber attack"

The satellite bot is designed to provide **independent contextual evidence**, not a direct verdict.
A satellite communication anomaly in isolation is just an anomaly.  But when:

- **Cyber Bot** detects PowerShell execution at 11:15
- **Intelligence Bot** reports the same IP is a known C2 node
- **Satellite Bot** reports a communication anomaly at the same time on a co-located asset

…the **Fusion Bot** can assign a high cross-source correlation confidence.

## Evidence Matrix

When the commander opens any fusion result, they see:

```
INCIDENT #1042
────────────────────────────────────

                    Evidence
Cyber Sensor           ✓  (2 events · Brute Force, Lateral Movement)
Intelligence Report    ✓  (1 report · IOC overlap: 100%)
Satellite              ✓  (2 events · max anomaly: 91%)

Cross-source correlation: 91%
Sources corroborating: 3/3
FP probability: 7% — Genuine Threat

MITRE ATT&CK
T1110 · T1003 · T1071 · T1021

Risk: 89  Priority: CRITICAL

WHY WAS THIS PRIORITIZED?
✓ All 3 independent sources corroborate the activity
✓ Threat intelligence confirms 100% of cyber indicators
✓ High-severity cyber event (92/100) from endpoint sensor
✓ Satellite anomaly observed within 15-minute window
✓ Analysts confirmed 2 previous events from this source as genuine
```

## False-positive model

FP probability is computed from **cross-source evidence**, not a single alert.

| Factor | FP score adjustment |
|---|---|
| Multi-source agreement (3 sources) | −20 |
| High-severity cyber event | −15 |
| Strong intel corroboration | −25 |
| Satellite anomaly corroborates | −12 |
| Only 1 source reports the activity | +15 |
| No intelligence corroboration | +18 |
| Analyst history: prior FP | +18 |
| Analyst history: prior TP | −18 |

FP score ≤ 25 → `GENUINE_THREAT` · 26–55 → `UNCERTAIN` · > 55 → `LIKELY_FALSE_POSITIVE`

The `UNCERTAIN` state is explicit — the system never forces every alert into TRUE/FALSE.

## Multi-source risk score

```
Cyber evidence        20%
Intel corroboration   20%
Satellite evidence    15%
Historical behaviour  15%
Cross-source corr     15%
Asset criticality     10%
Recency                5%
```

These weights are **configuration parameters** exposed via `GET/PUT /api/fusion/weights` so
analysts can tune them based on operational feedback.  They are not claims of universal correctness.

## Continuous learning dataset

`src/backend/data/historical/learning_dataset.json` uses the multi-source schema:

| Field | Description |
|---|---|
| `event_id` | Unique identifier |
| `source` | Bot that produced the event |
| `event_type` | Canonical MITRE-aligned type |
| `cyber_score` | Cyber Bot confidence (0.0–1.0) |
| `intel_score` | Intel Bot confidence (0.0–1.0) |
| `satellite_score` | Satellite Bot anomaly score (0.0–1.0) |
| `correlation_score` | Cross-source correlation |
| `sources_present` | Independent sources corroborating (1–3) |
| `analyst_label` | Ground truth: `TRUE_POSITIVE` / `FALSE_POSITIVE` |

This lets a future model learn **which combinations of evidence matter** — not just individual
alert types.

## Data layout

```
src/backend/data/
├── cyber/
│   ├── siem_events.json          SIEM authentication + lateral movement events
│   ├── network_events.json       Network sensor / IDS events
│   └── endpoint_events.json      EDR PowerShell, LSASS, firewall events
├── intelligence/
│   ├── threat_reports.json       CTI prose reports (unstructured + structured)
│   ├── iocs.json                 IOC feed (IP, domain, hash with reputation)
│   └── threat_feeds.json         ISAC advisories
├── satellite/
│   ├── telemetry.json            Satellite/ground-station telemetry streams
│   └── anomalies.json            Pre-classified anomaly events
└── historical/
    ├── incidents.json            Past confirmed incidents
    └── learning_dataset.json     Multi-source training data (schema v2)

src/backend/bots/
├── __init__.py
├── cyber_bot.py                  Bot 1 — normalise + confidence + MITRE candidate
├── intelligence_bot.py           Bot 2 — extract indicators + behaviours + MITRE
├── satellite_bot.py              Bot 3 — anomaly scoring + evidence description
└── fusion_bot.py                 Bot 4 — correlate + Evidence Matrix + FP + risk + BLUF data

src/backend/routes/
├── fusion.py                     POST /api/fusion/run  GET /api/fusion/live  GET /api/fusion/weights
└── …existing routes…

src/backend/sample_feeds/
├── satellite_telemetry.json      Satellite sample feed for the ingestion panel
└── …existing feeds…

src/frontend/src/components/
├── FusionPanel.jsx               Live 4-bot demo — "Run Live Demo" button
├── EvidenceMatrix.jsx            Evidence Matrix + "Why was this prioritized?"
└── …existing components…
```

## Live demo flow

1. Open the dashboard → click **▶ Run Live Demo** in the Fusion panel
2. Backend loads sample data for all three source bots
3. Bot 1 processes SIEM + EDR events → cyber events with IOCs and MITRE candidates
4. Bot 2 processes CTI reports → indicators, behaviours, MITRE techniques
5. Bot 3 processes satellite telemetry → anomaly scores and evidence descriptions
6. Bot 4 fuses all three → Evidence Matrix + risk score + FP probability + BLUF
7. Dashboard updates instantly with the full cross-source result
8. Analyst submits feedback → new labelled example added to the learning dataset

## Original single-pipeline architecture (still present)

The original `pipeline.assess()` pathway is unchanged — all existing ingest, alert detail and
Commander Brief routes still use it.  The 4-bot fusion layer is **additive**: it adds a new
`/api/fusion/` group alongside the existing API without modifying any existing endpoint.

See [bob-integration.md](bob-integration.md) for the BLUF prompt, the IBM Bob wire call and
the fallback contract.

## Security & scalability notes

* No authentication in this prototype; the API is intended to sit behind an SOC's existing gateway.
* Bob credentials are read from `src/backend/.env` only (never committed; `.env` is git-ignored).
* SQLite for portability; `DATABASE_URL` and the SQLAlchemy layer allow a PostgreSQL swap.
* Fusion weights are in-memory for the demo; in production they would be persisted per-deployment.
* Bot modules are pure functions — they can be moved to a queue worker (e.g. Kafka consumer per
  feed) without touching the fusion or assessment pipeline.
