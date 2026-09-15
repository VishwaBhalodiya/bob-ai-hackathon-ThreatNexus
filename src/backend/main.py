"""
ThreatNexus — FastAPI backend entry point.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import init_db
from app.routes import alerts, threats, assets, dashboard

app = FastAPI(
    title="ThreatNexus API",
    description="AI-Powered Threat Intelligence & Alert Prioritisation Platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def on_startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "service": "ThreatNexus API"}


# Mount route modules
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threat Intel"])
app.include_router(assets.router, prefix="/api/assets", tags=["Assets"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
