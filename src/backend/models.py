from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    asset_type = Column(String, nullable=False)       # e.g. "Server", "Laptop", "Domain Controller"
    criticality = Column(String, nullable=False)      # LOW, MEDIUM, HIGH, CRITICAL
    department = Column(String, nullable=False)

    alerts = relationship("Alert", back_populates="asset")


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    ioc_value = Column(String, nullable=False, index=True)
    ioc_type = Column(String, nullable=False)         # IP, DOMAIN, HASH, URL
    reputation = Column(Float, default=0.0)           # 0-100, higher = more malicious
    confidence = Column(Float, default=0.0)           # 0-100
    threat_type = Column(String, nullable=True)       # e.g. "Ransomware", "C2", "Phishing"
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    threat_events = relationship("ThreatEvent", back_populates="ioc")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String, nullable=False)
    destination_ip = Column(String, nullable=True)
    event_type = Column(String, nullable=False)       # e.g. "Port Scan", "Brute Force"
    severity = Column(String, nullable=False)         # LOW, MEDIUM, HIGH, CRITICAL
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    status = Column(String, default="OPEN")           # OPEN, IN_PROGRESS, RESOLVED
    risk_score = Column(Float, default=0.0)
    priority = Column(String, default="LOW")
    feedback = Column(String, default="UNREVIEWED")   # UNREVIEWED, TRUE_POSITIVE, FALSE_POSITIVE, ESCALATED
    feedback_at = Column(DateTime, nullable=True)
    source = Column(String, default="SIEM")           # SIEM, Firewall, IDS/IPS, EDR, Email Security, Vulnerability Scanner, Threat Intel Feed
    raw_log = Column(Text, nullable=True)             # original unstructured log line / feed text
    description = Column(Text, nullable=True)         # optional human-readable summary
    feed_format = Column(String, nullable=True)       # cef, syslog, json, csv, stix — how it arrived
    verdict = Column(String, default="NEEDS_REVIEW")  # GENUINE_THREAT, LIKELY_FALSE_POSITIVE, NEEDS_REVIEW
    verdict_confidence = Column(Float, default=0.0)   # 0-100
    mitre_technique_id = Column(String, nullable=True)  # e.g. T1110
    mitre_technique = Column(String, nullable=True)     # e.g. Brute Force
    mitre_tactic = Column(String, nullable=True)        # e.g. Credential Access
    iocs = Column(JSON, default=list)                   # [{type, value, found, reputation, threat_type}]

    asset = relationship("Asset", back_populates="alerts")
    threat_events = relationship("ThreatEvent", back_populates="alert")
    recommendations = relationship("Recommendation", back_populates="alert")


class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    ioc_id = Column(Integer, ForeignKey("iocs.id"), nullable=True)
    event_type = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    alert = relationship("Alert", back_populates="threat_events")
    ioc = relationship("IOC", back_populates="threat_events")


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    recommendation = Column(Text, nullable=False)
    generated_by = Column(String, default="ai_engine")
    created_at = Column(DateTime, default=datetime.utcnow)

    alert = relationship("Alert", back_populates="recommendations")
