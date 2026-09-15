"""
ORM models for ThreatNexus.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), unique=True, index=True, nullable=False)
    ip_address = Column(String(50), nullable=False)
    asset_type = Column(String(100))          # server, workstation, iot, cloud
    criticality = Column(Integer, default=5)  # 1-10 — used in risk weighting
    owner = Column(String(255))
    department = Column(String(255))
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

    alerts = relationship("Alert", back_populates="asset")


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String(50), nullable=False)   # ip, domain, hash, url, email
    ioc_value = Column(String(1024), nullable=False, index=True)
    reputation_score = Column(Float, default=0.0)   # 0-100 (100 = most malicious)
    threat_category = Column(String(255))           # c2, malware, phishing, scanner …
    source = Column(String(255))                    # e.g. "VirusTotal", "AlienVault OTX"
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    tags = Column(JSON, default=list)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text)
    source_system = Column(String(255))    # SIEM, IDS, Firewall …
    source_severity = Column(String(50))  # low / medium / high / critical (raw)
    raw_log = Column(Text)

    # Extracted IOCs (JSON list of {type, value})
    iocs = Column(JSON, default=list)

    # Linked asset
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    asset = relationship("Asset", back_populates="alerts")

    # Computed risk
    risk_score = Column(Float, default=0.0)         # 0-100
    risk_level = Column(String(50), default="LOW")  # LOW / MEDIUM / HIGH / CRITICAL
    ai_explanation = Column(Text)
    investigation_steps = Column(JSON, default=list)

    # Correlation
    correlation_group_id = Column(String(255), nullable=True, index=True)
    is_acknowledged = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)

    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
