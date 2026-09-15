# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Before you begin, ensure you have the following installed:

- [ ] Python 3.11 or newer
- [ ] Node.js 18 or newer and npm
- [ ] Git

Optional (for AI-assisted explanations):

- [ ] An IBM Cloud account with watsonx.ai access
- [ ] A watsonx.ai project ID and API key

## Repository Structure

```
src/
  backend/          ← FastAPI Python backend
    app/
      routes/       ← API route handlers
      services/     ← IOC extractor, risk scorer, correlator, AI explainer
      models.py     ← SQLAlchemy ORM models
      schemas.py    ← Pydantic request/response schemas
      seed.py       ← Demo data seeder
      database.py   ← DB connection and session factory
    main.py         ← FastAPI application entry point
    requirements.txt
  frontend/         ← React + Vite TypeScript SPA
    src/
      components/   ← AlertCard, AlertDetail, RiskBadge, IOCPanel, etc.
      App.tsx        ← Main layout + state
      api.ts         ← Typed fetch wrappers
      types.ts       ← TypeScript interfaces
    package.json
    vite.config.ts
```

## Environment Variables

Copy `.env.example` to `.env` and fill in values:

```bash
cp src/.env.example src/.env
```

| Variable | Description | Required |
|---|---|---|
| `WATSONX_API_KEY` | IBM watsonx.ai API key | No — uses template fallback if absent |
| `WATSONX_PROJECT_ID` | watsonx.ai project ID | No — uses template fallback if absent |
| `WATSONX_URL` | watsonx.ai region endpoint | No — defaults to `us-south` |
| `WATSONX_MODEL_ID` | Granite model ID | No — defaults to `ibm/granite-3-8b-instruct` |
| `DATABASE_URL` | SQLAlchemy DB URL | No — defaults to `sqlite:///./threatenexus.db` |
| `APP_PORT` | Backend port | No — defaults to `8000` |

## Installation

### Backend

```bash
cd src/backend

# Create and activate a virtual environment
python -m venv venv

# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend

```bash
cd src/frontend
npm install
```

## Running the Application

### 1. Start the backend (terminal 1)

```bash
cd src/backend
# Activate venv first if not already active
uvicorn main:app --reload --port 8000
```

The backend will:
- Create `threatenexus.db` (SQLite) automatically on first run
- Seed demo assets, threat intelligence, and pre-enriched alerts
- Serve the REST API at `http://localhost:8000`
- Expose interactive API docs at `http://localhost:8000/docs`

### 2. Start the frontend (terminal 2)

```bash
cd src/frontend
npm run dev
```

The dashboard will be available at: **`http://localhost:5173`**

## Quick Demo

The database seeds automatically on first launch. Open `http://localhost:5173` and you will see:

- 6 pre-seeded alerts ranging from 🔴 CRITICAL (APT C2 beacon) to 🟢 LOW (DNS anomaly)
- 8 threat intelligence records from AlienVault OTX, VirusTotal, PhishTank, Shodan
- 6 assets including domain controllers, database servers, and workstations
- 3 correlated alerts grouped into an APT campaign storyline

To ingest a new alert manually:

```bash
curl -X POST http://localhost:8000/api/alerts/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Malware C2 beacon detected",
    "description": "Host attempted connection to 185.220.101.47 on port 443.",
    "source_system": "EDR",
    "source_severity": "high",
    "asset_hostname": "dc01.corp.internal"
  }'
```

## Running Tests

```bash
cd src/backend
pytest tests/ -v
```

## Troubleshooting

| Issue | Solution |
|---|---|
| `ModuleNotFoundError` | Ensure your virtual environment is activated and `pip install -r requirements.txt` completed successfully |
| Frontend shows "Failed to load data" | Confirm the backend is running on port 8000 — check terminal 1 |
| watsonx.ai 401 error | Check `WATSONX_API_KEY` and `WATSONX_PROJECT_ID` in `.env`; the platform works without them |
| Port 8000 already in use | Use `uvicorn main:app --reload --port 8001` and update `vite.config.ts` proxy target |
| SQLite database locked | Stop all backend instances and restart with a single `uvicorn` process |
