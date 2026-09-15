# ThreatNexus — Threat Intelligence Correlation & Alert Prioritisation Assistant

**Bob AI Innovation Hackathon · Track: AI · Challenge D2 (Critical Now)**

| | |
|---|---|
| **Team** | ThreatNexus |
| **Lead** | Diya Macwan |
| **Members** | Diya Macwan · Vishwa Bhalodiya · Dhruvi Bhanderi · Tanish Mahyavanshi |
| **IBM technology** | IBM Bob — inference API generates every BLUF summary; Bob agent used to build the solution |

---

## Problem statement

Defence analysts receive thousands of alerts daily from SIEM systems, satellite feeds, cyber
sensors and intelligence reports — all in different formats. No human team can read them all.
Missing a genuine threat is catastrophic; chasing false positives wastes critical resources.
Threat assessments must reach commanders as structured **BLUF (Bottom Line Up Front)** so they get
a clear picture in minutes. See [docs/problem-statement.md](docs/problem-statement.md).

## Solution

ThreatNexus **ingests multi-source feeds in their native formats**, **correlates** alerts across
actors, assets and time to **separate genuine threats from false positives**, **maps attacker
techniques to MITRE ATT&CK**, and generates **prioritised BLUF investigation summaries** — per
alert and as a Commander Brief. IBM Bob writes the BLUF text; a deterministic template takes over
if Bob is unavailable, so the demo never depends on the network.

```
CEF · syslog/Suricata · JSON · CSV · STIX 2.1
        │  auto-detect → normalise → de-duplicate → link asset
        ▼
 enrich (every IOC in the log) → correlate (actor / asset / time) → risk score
        ▼
 verdict: GENUINE · NEEDS REVIEW · LIKELY FALSE POSITIVE   (learns from analyst feedback)
        ▼
 MITRE ATT&CK technique + tactic → multi-stage attack-chain detection
        ▼
 IBM Bob → BLUF: bottom line · situation · assessment · recommendation
        ▼
 Commander Brief: posture · headline · chains · ranked priorities · suppressed noise
```

## Key features

1. **Multi-format ingestion** — `POST /api/ingest` accepts CEF, syslog (incl. Suricata/Snort
   fast-log and key=value), JSON/NDJSON with nested fields, CSV and STIX 2.1 bundles. Records are
   normalised to one schema, de-duplicated across feeds (±90 s), and linked to the asset inventory.
   Five realistic sample feeds ship with the app — one click ingests them all.
2. **Genuine vs false positive** — every alert gets a verdict with confidence and the signals
   behind it (IOC reputation, corroboration, chain membership, asset criticality, behaviour,
   analyst history). Analyst triage (`TRUE_POSITIVE` / `FALSE_POSITIVE` / `ESCALATED`) re-scores the
   alert instantly and becomes a learning signal for future alerts from the same actor.
3. **MITRE ATT&CK** — free-text feed events resolve to technique ID, name and tactic
   (`"Mimikatz-like LSASS access"` → T1003 · Credential Access). Kill-chain coverage strip on the
   dashboard; attack chains flagged when correlated alerts span ≥3 tactics *and* include a genuine alert.
4. **Commander Brief** (`/brief`) — threat posture, one-sentence bottom line, situation /
   assessment / recommendation, active chains with their stage progression, ranked *distinct*
   threats (correlated duplicates collapsed) each with a four-part BLUF, and the noise that was
   suppressed — with the reason, so nothing is hidden from command. Print-ready.
5. **IBM Bob** — all BLUF prose is produced by the Bob inference API; the header badge shows
   whether Bob or the template fallback is live, with call counters. See
   [docs/bob-integration.md](docs/bob-integration.md).
6. **Explainable risk** — weighted score (severity 25 % · IOC reputation 25 % · asset criticality
   20 % · behaviour 15 % · correlation 15 %) with a per-alert breakdown chart. IOC reputation is
   the strongest indicator *anywhere in the log* — a low-reputation source IP delivering a link to
   a known phishing domain scores on the domain.

## Tech stack

| Category | Technologies |
|---|---|
| *Languages* | Python, JavaScript / TypeScript, HTML, CSS |
| *Frameworks* | FastAPI, React.js, Vite |
| *AI Technologies* | IBM Bob AI, LLM-based threat explanation |
| *Databases* | SQLite |
| *Data Processing* | Python, Pydantic, SQLAlchemy |
| *Visualization* | Recharts |
| *API* | REST APIs |
| *Development Tools* | Git, GitHub, VS Code, Postman |
| *Other* |  MITRE ATT&CK · STIX 2.1 · CEF |

## How to run

```bash
# backend  →  http://localhost:8000  (OpenAPI docs at /docs)
cd src/backend
pip install -r requirements.txt
python seed.py
uvicorn main:app --reload
```

```bash
# frontend →  http://localhost:5173
cd src/frontend
npm install
npm run dev
```

Then: open the dashboard → **⇣ Ingest all sample feeds** → **▤ Commander Brief**.
To route BLUF generation through IBM Bob, copy `src/.env.example` to `src/backend/.env` and set
`BOB_ENABLED=true`, `BOB_API_KEY`, `BOB_BASE_URL`, `BOB_MODEL`. Full details, verification steps
and troubleshooting in [docs/setup-guide.md](docs/setup-guide.md).

```bash
# tests (34)
cd src/backend && python -m pytest
```

## Demo

- Video: [demo/demo-video-link.txt](demo/demo-video-link.txt)
- Live: [demo/live-demo-url.txt](demo/live-demo-url.txt)
- Screenshots: [demo/screenshots/](demo/screenshots/)

## Known limitations

- No authentication; not production-hardened.
- Threat intel is a local IOC table fed by STIX / the API — no live VirusTotal / MISP connector.
- Feeds arrive over REST (paste or POST); no persistent SIEM/syslog listeners.
- Without Bob credentials the BLUF text is template-generated (clearly labelled in the UI).
- SQLite for local development.

## What we're most proud of

One assessment pipeline behind every path — ingest, detail view, analyze, rescore and the brief —
so the dashboard list, the detail page and the Commander Brief can never disagree. Paste a raw
Suricata log, a Palo Alto CEF line and a STIX bundle and within seconds the brief reads
*"CRITICAL — isolate DC01.corp.local now; 45.155.204.18 has progressed through Initial Access →
Execution → Privilege Escalation → Credential Access → Command & Control in 7 correlated
alerts"*, while the port scans from an unknown IP sit underneath as suppressed noise, with the reason.

## Repository layout

```
submission.yaml          structured metadata (read first by evaluators)
docs/                    problem · solution · architecture · setup · bob-integration
src/backend/             FastAPI service, engines, sample feeds, tests
src/frontend/            React dashboard, alert detail, Commander Brief
demo/                    video link · live URL · screenshots
presentation/            slide deck
```
