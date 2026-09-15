from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import ensure_schema
import models  # noqa: F401 – ensure all models are registered before create_all

from routes import alerts, iocs, dashboard, ingest, brief, assets

# ── Create all tables + add any new columns ───────────────────────────────────
ensure_schema()

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatNexus API",
    description="Multi-source threat-feed ingestion, correlation, MITRE ATT&CK mapping and BLUF prioritisation — AI summaries by IBM Bob",
    version="1.0.0",
)

# ── CORS (allow all origins for local frontend dev) ───────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(alerts.router)
app.include_router(iocs.router)
app.include_router(assets.router)
app.include_router(dashboard.router)
app.include_router(ingest.router)
app.include_router(brief.router)


@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "service": "ThreatNexus API"}
