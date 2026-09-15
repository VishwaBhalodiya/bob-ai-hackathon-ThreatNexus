# 🛡️ ThreatNexus

> **AI-Powered Threat Intelligence & Alert Prioritisation Platform**

ThreatNexus helps Security Operations Centre analysts answer the question every SOC faces hundreds of times a day:
**"Which alert should I investigate first?"**

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | ThreatNexus |
| **Track** | AI |
| **Team Lead** | Diya Macwan — macwandiya8@gmail.com |
| **Members** | Vishwa Bhalodiya, Dhruvi Bhanderi, Diya Macwan, Tanish Mahyavanshi |

---

## 🎯 Problem Statement

Security analysts receive thousands of alerts from SIEM systems, security sensors, threat-intelligence feeds and other sources. Because these alerts contain different levels of severity, context and reliability, analysts struggle to identify which threats require immediate attention, leading to alert fatigue and the risk of missing critical attacks.

ThreatNexus addresses this problem by helping security analysts understand, correlate and prioritise alerts based on threat intelligence, asset criticality, behavioural indicators and related security events.

---

## 💡 Solution

ThreatNexus is an AI-assisted threat intelligence and alert prioritisation platform that converts large numbers of security alerts into a ranked list of actionable threats.

The platform extracts and enriches Indicators of Compromise (IOCs), combines threat reputation with asset context and behavioural information, correlates related events into attack stories, and calculates an explainable risk score from 0–100. IBM watsonx.ai (Granite model) then provides a concise explanation of why an alert is important and recommends investigation steps for the analyst.

**Output:**
- 🔴 **CRITICAL** (80–100) — Investigate Immediately
- 🟠 **HIGH** (60–79) — Investigate Soon
- 🟡 **MEDIUM** (35–59) — Monitor / Investigate
- 🟢 **LOW** (0–34) — Low Priority

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **Context-Aware Risk Scoring** | Weighted formula combining source severity, IOC reputation, asset criticality, threat category behaviour, and correlation |
| **IOC Extraction & Enrichment** | Regex-based extraction of IPs, domains, URLs, hashes, and emails; automatic lookup against threat intel DB |
| **Alert Correlation** | Shared-IOC and same-asset grouping within a 4-hour window produces attack storylines |
| **AI Threat Explanation** | IBM watsonx.ai (Granite 3 8B) generates plain-English explanations and 4 concrete investigation steps |
| **Asset Criticality Context** | The same IOC on a domain controller (criticality 10) scores higher than on a lobby camera (criticality 3) |
| **SOC Analyst Dashboard** | Dark-mode React dashboard: prioritised alert queue, risk donut chart, IOC chips, threat intel feed, side-panel detail |

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python 3.11, TypeScript, HTML, CSS |
| **Backend** | FastAPI, SQLAlchemy, Pydantic, Uvicorn |
| **Frontend** | React 18, Vite, Recharts, lucide-react |
| **AI Technologies** | IBM watsonx.ai (Granite 3 8B Instruct via `ibm-watsonx-ai` SDK) |
| **Database** | SQLite (development) / PostgreSQL-ready |
| **Development Tools** | Git, GitHub, VS Code, Postman |

---

## 📁 Repository Structure

```
├── src/
│   ├── backend/              ← FastAPI Python backend
│   │   ├── app/
│   │   │   ├── routes/       ← alerts, threats, assets, dashboard
│   │   │   ├── services/     ← ioc_extractor, risk_scorer, alert_correlator, ai_explainer, pipeline
│   │   │   ├── models.py     ← SQLAlchemy ORM
│   │   │   ├── schemas.py    ← Pydantic schemas
│   │   │   ├── seed.py       ← Demo data seeder
│   │   │   └── database.py
│   │   ├── main.py
│   │   └── requirements.txt
│   └── frontend/             ← React + Vite SPA
│       ├── src/
│       │   ├── components/   ← AlertCard, AlertDetail, RiskBadge, IOCPanel, StatsBar, RiskChart, ThreatIntelPanel
│       │   ├── App.tsx
│       │   ├── api.ts
│       │   └── types.ts
│       ├── package.json
│       └── vite.config.ts
├── docs/
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/
└── submission.yaml
```

---

## ⚡ How to Run

```bash
# 1. Clone the repo
git clone https://github.com/diya-macwan/bob-ai-hackathon-ThreatNexus.git
cd bob-ai-hackathon-ThreatNexus

# 2. Backend
cd src/backend
python -m venv venv && venv\Scripts\activate   # Windows
# source venv/bin/activate                       # macOS/Linux
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# 3. Frontend (new terminal)
cd src/frontend
npm install
npm run dev
```

Open **http://localhost:5173** — the dashboard loads with pre-seeded demo data immediately.

> Full setup instructions: [`docs/setup-guide.md`](docs/setup-guide.md)

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |
| 📖 API Docs | `http://localhost:8000/docs` (auto-generated Swagger UI) |

---

## ⚠️ Known Limitations

- **No authentication** — all API endpoints are unauthenticated. Not production-ready.
- **SQLite only** — designed for local demo use; production requires PostgreSQL.
- **No real SIEM connector** — alerts are ingested via REST API; live SIEM integration is not implemented.
- **watsonx.ai is optional** — if credentials are not supplied, a deterministic template generates explanations. The template explanations are useful but less contextual than the Granite model output.
- **IOC extraction is regex-based** — works well for structured logs; unstructured prose text may miss some indicators.

---

## 🏅 What We're Most Proud Of

The **end-to-end enrichment pipeline** that runs in a single REST call: IOC extraction → threat intel lookup → asset criticality resolution → weighted risk scoring with full component breakdown → alert correlation → AI explanation. Every alert that enters ThreatNexus exits with a risk score, a plain-English explanation, and four concrete investigation steps — ready for the analyst to act on immediately without any manual research.

The **graceful IBM watsonx.ai integration** is also worth highlighting: the platform works identically with or without API credentials, making it easy to demo offline while being fully production-capable when credentials are present.

---
