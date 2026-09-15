# Architecture

## System diagram

```mermaid
graph TD
    subgraph Feeds["Threat feeds (native formats)"]
        FW[Firewall / WAF<br/>CEF]
        IDS[IDS / IPS<br/>syslog · Suricata fast-log]
        SIEM[SIEM / EDR<br/>JSON · NDJSON · CSV]
        TI[Threat-intel sharing<br/>STIX 2.1]
    end

    subgraph API["FastAPI backend (src/backend)"]
        ING[routes/ingest.py<br/>POST /api/ingest]
        FI[services/feed_ingestor.py<br/>detect · parse · normalise]
        PIPE[services/pipeline.py<br/>assess()]
        TIS[threat_intelligence.py<br/>IOC enrichment]
        IOCX[ioc_extractor.py<br/>IPs · domains · URLs · hashes]
        CORR[correlation_engine.py<br/>clusters · siblings · chains]
        RISK[risk_engine.py<br/>weighted 0-100 score]
        FP[fp_classifier.py<br/>genuine / review / likely-FP]
        MITRE[mitre_mapper.py<br/>technique · tactic · kill-chain]
        AI[ai_engine.py<br/>BLUF via IBM Bob]
        BRIEF[routes/brief.py<br/>GET /api/brief]
        DB[(SQLite<br/>assets · iocs · alerts · events)]
    end

    BOB[[IBM Bob inference API<br/>chat/completions]]

    subgraph UI["React frontend (src/frontend)"]
        DASH[Dashboard<br/>ingest panel · stats · ATT&CK strip · alert table]
        DET[Alert Detail<br/>BLUF · verdict · risk breakdown · timeline · triage]
        CB[Commander Brief<br/>posture · chains · ranked BLUFs · suppressed]
    end

    FW --> ING
    IDS --> ING
    SIEM --> ING
    TI --> ING
    ING --> FI --> PIPE
    PIPE --> IOCX --> TIS
    PIPE --> CORR
    PIPE --> RISK
    PIPE --> FP
    PIPE --> MITRE
    PIPE --> AI
    AI -->|prompt: score breakdown,<br/>verdict signals, MITRE| BOB
    BOB -->|JSON BLUF| AI
    AI -.->|timeout / error| AI
    PIPE --> DB
    TIS --> DB
    CORR --> DB
    DB --> BRIEF
    BRIEF --> PIPE
    DASH --> ING
    DASH --> DB
    DET --> PIPE
    CB --> BRIEF
```

## Components

| Component | Technology | Responsibility |
|---|---|---|
| `routes/ingest.py` | FastAPI | Accepts raw feed text or JSON, dispatches to the parser, de-duplicates, links assets, persists, re-scores neighbours; serves bundled sample feeds |
| `services/feed_ingestor.py` | Python, `re`, `csv`, `json` | Format detection and five parsers → one canonical record; STIX → IOC dicts |
| `services/pipeline.py` | Python | **The** assessment path: enrich → correlate → score → verdict → MITRE → BLUF; `assess_alert()` for stored rows; `rescore_all()` |
| `services/ioc_extractor.py` | regex | Pure extraction of IPs, domains, URLs, hashes, e-mails from log text |
| `services/threat_intelligence.py` | SQLAlchemy | IOC reputation / confidence / threat-type lookup (swap body for a live TI API) |
| `services/correlation_engine.py` | SQLAlchemy | 24 h clusters, ±10 min siblings, attack-chain detection by tactic spread |
| `services/risk_engine.py` | Python | 0.25·severity + 0.25·IOC + 0.20·asset + 0.15·behaviour + 0.15·correlation → priority |
| `services/fp_classifier.py` | Python | Explainable genuine / needs-review / likely-FP verdict; analyst-history learning |
| `services/mitre_mapper.py` | Python | Event → ATT&CK technique/tactic; alias resolver; kill-chain order |
| `services/ai_engine.py` | `requests` → **IBM Bob** | BLUF prompt, Bob chat/completions call, JSON validation, template fallback, status counters |
| `routes/brief.py` | FastAPI | Commander Brief, attack chains, MITRE coverage |
| `routes/alerts.py`, `dashboard.py`, `assets.py`, `iocs.py` | FastAPI | Alert list/detail/feedback/status/rescore, stats, analyze, AI status, asset & IOC CRUD |
| `database.py` | SQLAlchemy + SQLite | Engine anchored to `src/backend/`, `ensure_schema()` adds new columns on start-up |
| `src/frontend` | React 18, Vite, Recharts | Dashboard, Alert Detail, Commander Brief; `AiEngineBadge` polls `/api/ai/status` |

## Data flow, end to end

1. **Ingest.** A feed payload hits `POST /api/ingest {payload, format, source}`. `feed_ingestor.parse()`
   sniffs the format, parses each record, normalises event names via `mitre_mapper.normalise_event_type()`
   and severities onto LOW–CRITICAL.
2. **De-duplicate & link.** Each record is checked against existing alerts (same actor, event,
   target, ±90 s) and linked to an `Asset` by destination IP or hostname.
3. **Assess.** `pipeline.assess()`:
   - looks up the source IP and every IOC extracted from the log (URLs and e-mails are also
     looked up by host/domain); the strongest reputation drives the score;
   - counts 24 h correlated alerts and fetches ±10 min siblings; classifies an attack chain if the
     siblings span ≥3 tactics;
   - computes the weighted risk score and priority;
   - runs the false-positive classifier with the analyst history for that actor/technique;
   - maps the event to ATT&CK;
   - (on demand) builds the BLUF prompt and calls **IBM Bob**, validating the JSON and falling
     back to the template on timeout or error.
4. **Persist.** `Alert` row plus `ThreatEvent` and `Recommendation` children; score, verdict,
   MITRE fields and matched IOCs are stored so the list view is cheap. Neighbours of the new
   alert are re-assessed so their correlation reflects the new arrival.
5. **Brief.** `GET /api/brief` buckets the window's alerts by verdict, detects chains, ranks
   distinct threats, generates each one's BLUF and composes posture + headline.
6. **Feedback.** `PATCH /api/alerts/{id}/feedback` re-assesses the alert and updates the history
   used for future verdicts; `PATCH /api/alerts/{id}/status` moves it through the workflow.

## IBM Bob integration

See [bob-integration.md](bob-integration.md) for the prompt, the wire call, the fallback contract
and how to verify Bob is live from the UI.

## Security & scalability notes

* No authentication in this prototype; the API is intended to sit behind an SOC's existing gateway.
* Bob credentials are read from `src/backend/.env` only (never committed; `.env` is git-ignored).
* SQLite is used for portability; `DATABASE_URL` and the SQLAlchemy layer allow a PostgreSQL swap
  without code changes to the services.
* Parsers are pure functions over text — they can be moved to a queue worker (e.g. Kafka consumer
  per feed) without touching the assessment pipeline.
* Bob calls are bounded by `BOB_TIMEOUT`; the brief uses templates by default and opts into Bob
  per request (`?llm=true`) so one page load never fans out into N unbounded model calls.
