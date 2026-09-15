# Setup Guide

Written for someone who has never seen this repo. Total time on a clean machine: ~5 minutes.

## Prerequisites

| Tool | Version | Check |
|---|---|---|
| Python | 3.11 or newer (tested on 3.14) | `python --version` |
| Node.js + npm | Node 18 or newer (tested on 26) | `node --version` |
| Git | any | `git --version` |
| IBM Bob API key *(optional)* | Inference-scoped key | only needed for Bob-generated BLUF text |

No Docker, no database server — SQLite is created automatically.

## 1. Clone

```bash
git clone https://github.com/<your-org>/bob-ai-hackathon-ThreatNexus.git
cd bob-ai-hackathon-ThreatNexus
```

## 2. Backend

```bash
cd src/backend
pip install -r requirements.txt
python seed.py
uvicorn main:app --reload
```

`seed.py` creates `threatenexus.db` with 8 assets, 11 IOCs and 23 alerts (including a 5-stage
attack chain), then runs the full assessment pipeline over them. You should see:

```
[OK] Seeded 8 assets, 11 IOCs, 23 alerts.
[OK] Pipeline pass: 23 alerts scored, verdicts + MITRE mapping stored.
[OK] Attack chain seeded: alerts 19-23 on 45.155.204.18 -> DC01.corp.local
```

The API is now at **http://localhost:8000** — interactive docs at http://localhost:8000/docs.

## 3. Frontend

Open a second terminal:

```bash
cd src/frontend
npm install
npm run dev
```

The dashboard is at **http://localhost:5173**.

## 4. Environment variables (optional — IBM Bob)

Without any `.env`, ThreatNexus runs in **template mode**: every BLUF is produced by the
deterministic template and the header badge reads *IBM Bob · template mode*.

To have IBM Bob write the BLUF summaries:

```bash
cp src/.env.example src/backend/.env
```

| Variable | Required | Description |
|---|---|---|
| `BOB_ENABLED` | yes | `true` to route BLUF generation through Bob |
| `BOB_API_KEY` | yes | Bob API key (create an *Inference-scoped* key in your Bob instance) |
| `BOB_BASE_URL` | yes | Bob inference base URL, no trailing slash — requests go to `{BOB_BASE_URL}/v1/chat/completions` |
| `BOB_MODEL` | yes | Model ID available on your Bob instance |
| `BOB_TIMEOUT` | no | Seconds before falling back to the template (default `3`) |
| `BOB_TEAM_ID` | no | Only for Bob *General* keys — sent as `X-Team-ID` |

Restart uvicorn after editing `.env`. The badge switches to *IBM Bob · <model>* and
`GET /api/ai/status` reports `"mode": "bob"` with live call counters.

## 5. Verify it works

1. **Dashboard** — http://localhost:5173 shows 23 alerts, 8 stat cards, the MITRE ATT&CK strip
   with one active attack chain.
2. **Ingest** — click **⇣ Ingest all sample feeds**. Five feeds (CEF, syslog, JSON, CSV, STIX)
   are pushed through the pipeline; the result panel reports records / new alerts / de-duplicated /
   IOCs added, and the stat cards update (23 → ~41 alerts, 1 → ~4 chains). Click it again: every
   record is reported as a duplicate — nothing is double-counted.
3. **Alert detail** — click any row. You get the BLUF, the correlation verdict with its reasons,
   the IOC chips, the risk breakdown, the ATT&CK mapping and (for chain members) the timeline.
   Click **✕ False Positive** — the verdict flips to *Likely FP · 97 %* instantly.
4. **Commander Brief** — click **▤ Commander Brief**. Posture, headline bottom line, active
   chains with stage progression, ranked priorities and suppressed noise. **⎙ Print** gives a
   hand-out.
5. **API** — `curl localhost:8000/api/brief?limit=3` returns the same brief as JSON.

## 6. Tests

```bash
cd src/backend
python -m pytest          # 34 tests: parsers, engines, end-to-end API
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Dashboard shows *Backend unreachable* | uvicorn not running on :8000, or started from a different directory. Run it from `src/backend`. |
| `ModuleNotFoundError: services` | Run `python seed.py` / `uvicorn` from `src/backend` (imports are relative to it). |
| Port 5173 / 8000 already in use | `uvicorn main:app --port 8001` and change `BASE` in `src/frontend/src/services/api.js`; or `npm run dev -- --port 5174`. |
| Badge says *template mode* although `.env` is set | `.env` must be at `src/backend/.env`; `BOB_ENABLED=true` (lower-case); restart uvicorn. Check `GET /api/ai/status` → `configured`. |
| Bob configured but BLUF text still looks templated | Check `GET /api/ai/status` → `stats.last_error`. Common causes: wrong `BOB_BASE_URL` (must be the inference base, no `/v1`), General key without `BOB_TEAM_ID`, timeout too low. |
| Reset the data | Stop uvicorn, `python seed.py`, start again. |
| Old `threatenexus.db` from a previous version | Start-up auto-adds missing columns (`ensure_schema`). If in doubt, delete the file and re-seed. |
