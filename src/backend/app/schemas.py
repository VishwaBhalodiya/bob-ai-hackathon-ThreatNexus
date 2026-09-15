"""
Pydantic schemas for request/response serialisation.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, List, Optional
from pydantic import BaseModel, Field


# ─── Asset ────────────────────────────────────────────────────────────────────

class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    asset_type: Optional[str] = None
    criticality: int = Field(default=5, ge=1, le=10)
    owner: Optional[str] = None
    department: Optional[str] = None
    tags: List[str] = []


class AssetCreate(AssetBase):
    pass


class AssetOut(AssetBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Threat Intel ─────────────────────────────────────────────────────────────

class ThreatIntelBase(BaseModel):
    ioc_type: str
    ioc_value: str
    reputation_score: float = Field(default=0.0, ge=0, le=100)
    threat_category: Optional[str] = None
    source: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = []


class ThreatIntelCreate(ThreatIntelBase):
    pass


class ThreatIntelOut(ThreatIntelBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


# ─── IOC ──────────────────────────────────────────────────────────────────────

class IOCItem(BaseModel):
    type: str   # ip, domain, hash, url, email
    value: str


# ─── Alert (ingest) ───────────────────────────────────────────────────────────

class AlertIngest(BaseModel):
    title: str
    description: Optional[str] = None
    source_system: Optional[str] = None
    source_severity: Optional[str] = "medium"
    raw_log: Optional[str] = None
    asset_hostname: Optional[str] = None  # resolved to asset_id internally


# ─── Alert (output) ───────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    source_system: Optional[str]
    source_severity: Optional[str]
    raw_log: Optional[str]
    iocs: List[IOCItem]
    asset: Optional[AssetOut]
    risk_score: float
    risk_level: str
    ai_explanation: Optional[str]
    investigation_steps: List[str]
    correlation_group_id: Optional[str]
    is_acknowledged: bool
    is_false_positive: bool
    timestamp: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ─── Dashboard ────────────────────────────────────────────────────────────────

class RiskDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class DashboardStats(BaseModel):
    total_alerts: int
    unacknowledged: int
    risk_distribution: RiskDistribution
    top_threats: List[ThreatIntelOut]
    recent_critical: List[AlertOut]
    correlation_groups: int
