from pydantic import BaseModel
from typing import Optional, List, Union
from datetime import datetime


# ── Asset ────────────────────────────────────────────────────────────────────

class AssetBase(BaseModel):
    hostname: str
    ip_address: str
    asset_type: str
    criticality: str
    department: str


class AssetCreate(AssetBase):
    pass


class AssetResponse(AssetBase):
    id: int

    class Config:
        from_attributes = True


# ── IOC ──────────────────────────────────────────────────────────────────────

class IOCBase(BaseModel):
    ioc_value: str
    ioc_type: str
    reputation: float = 0.0
    confidence: float = 0.0
    threat_type: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class IOCCreate(IOCBase):
    pass


class IOCResponse(IOCBase):
    id: int

    class Config:
        from_attributes = True


# ── Recommendation ────────────────────────────────────────────────────────────

class RecommendationResponse(BaseModel):
    id: int
    alert_id: int
    recommendation: str
    generated_by: str
    created_at: datetime

    class Config:
        from_attributes = True


# ── AIExplanation (BLUF format) ───────────────────────────────────────────────

class AIExplanation(BaseModel):
    """
    Bottom Line Up Front — four-field structured explanation.
    bottom_line: one sentence, verdict + required action, starts with priority level.
    situation:   1-2 sentences, what was observed.
    assessment:  1-2 sentences, why it is dangerous.
    recommendation: actionable remediation steps.
    """
    bottom_line:    str
    situation:      str
    assessment:     str
    recommendation: str


# ── ThreatEvent ───────────────────────────────────────────────────────────────

class ThreatEventResponse(BaseModel):
    id: int
    alert_id: int
    ioc_id: Optional[int] = None
    event_type: str
    description: Optional[str] = None
    timestamp: datetime

    class Config:
        from_attributes = True


# ── RelatedEvent ──────────────────────────────────────────────────────────────

class RelatedEventResponse(BaseModel):
    """A sibling alert returned as part of the related_events correlation field."""
    id: int
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    priority: str
    risk_score: float
    status: str
    asset_id: Optional[int] = None
    verdict: Optional[str] = None
    mitre_tactic: Optional[str] = None


# ── Verdict ───────────────────────────────────────────────────────────────────

class VerdictResponse(BaseModel):
    """Genuine-vs-false-positive classification with its explaining signals."""
    verdict:    str          # GENUINE_THREAT | LIKELY_FALSE_POSITIVE | NEEDS_REVIEW
    confidence: float        # 0-100
    score:      float        # 0-100 genuineness score
    reasons:    List[str] = []


class MitreResponse(BaseModel):
    technique_id: str
    technique:    str
    tactic:       str
    url:          str


# ── Alert ─────────────────────────────────────────────────────────────────────

FEEDBACK_VALUES = {"UNREVIEWED", "TRUE_POSITIVE", "FALSE_POSITIVE", "ESCALATED"}


class AlertBase(BaseModel):
    source_ip: str
    destination_ip: Optional[str] = None
    event_type: str
    severity: str
    asset_id: Optional[int] = None
    status: str = "OPEN"
    risk_score: float = 0.0
    priority: str = "LOW"
    feedback: str = "UNREVIEWED"
    feedback_at: Optional[datetime] = None
    source: str = "SIEM"
    raw_log: Optional[str] = None
    description: Optional[str] = None
    feed_format: Optional[str] = None
    verdict: Optional[str] = "NEEDS_REVIEW"
    verdict_confidence: Optional[float] = 0.0
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    iocs: List[dict] = []


class AlertCreate(AlertBase):
    timestamp: Optional[datetime] = None


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime

    class Config:
        from_attributes = True


class AlertDetailResponse(AlertResponse):
    asset: Optional[AssetResponse] = None
    threat_events: List[ThreatEventResponse] = []
    recommendations: List[RecommendationResponse] = []
    ioc_info: Optional[IOCResponse] = None
    risk_breakdown: Optional[dict] = None
    # ai_explanation is the full BLUF object; kept as Union for graceful
    # handling of any legacy str values during migration.
    ai_explanation: Optional[Union[AIExplanation, str]] = None
    related_events: List[RelatedEventResponse] = []
    is_attack_chain: bool = False
    correlation_count: int = 0
    verdict_detail: Optional[VerdictResponse] = None
    mitre: Optional[MitreResponse] = None
    extracted_iocs: List[dict] = []

    class Config:
        from_attributes = True


# ── Feedback ──────────────────────────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    feedback: str  # must be one of FEEDBACK_VALUES — validated in the route


STATUS_VALUES = {"OPEN", "IN_PROGRESS", "RESOLVED"}


class StatusRequest(BaseModel):
    status: str    # OPEN | IN_PROGRESS | RESOLVED — validated in the route


class FeedbackSummary(BaseModel):
    unreviewed: int
    true_positive: int
    false_positive: int
    escalated: int


# ── Dashboard ─────────────────────────────────────────────────────────────────

class VerdictSummary(BaseModel):
    genuine: int
    likely_false_positive: int
    needs_review: int


class DashboardResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    feedback_summary: FeedbackSummary
    verdict_summary: VerdictSummary
    sources_breakdown: dict   # {source_name: count}
    formats_breakdown: dict   # {feed_format: count}
    tactic_breakdown: dict    # {mitre_tactic: count}
    attack_chains: int        # multi-stage chains in the last 24 h


# ── Analyze ───────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    source_ip: str
    event_type: str
    asset_id: Optional[int] = None
    severity: str = "MEDIUM"
    raw_text: Optional[str] = None   # log / description — IOCs inside are scored too


class AnalyzeResponse(BaseModel):
    risk_score: float
    priority: str
    confidence: float
    recommendation: str
    ai_explanation: Union[AIExplanation, str]
    risk_breakdown: dict
    ioc_info: Optional[IOCResponse] = None
    verdict: Optional[VerdictResponse] = None
    mitre: Optional[MitreResponse] = None
    correlation_count: int = 0
    is_attack_chain: bool = False
    iocs: List[dict] = []


# ── Ingest ────────────────────────────────────────────────────────────────────

class IngestRequest(BaseModel):
    """
    payload: raw feed text (CEF lines, syslog lines, JSON/NDJSON, CSV or a
             STIX 2.1 bundle).  A JSON array/object may also be passed directly.
    format:  auto | cef | syslog | json | csv | stix
    source:  default feed label when the record itself does not say
             (SIEM, Firewall, IDS/IPS, EDR, Email Security, Threat Intel Feed…)
    """
    payload: Union[str, list, dict]
    format: str = "auto"
    source: Optional[str] = None


class IngestSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    genuine: int = 0
    likely_false_positive: int = 0
    needs_review: int = 0
    attack_chains: int = 0


class IngestResponse(BaseModel):
    format: str
    source: Optional[str] = None
    received: int
    ingested: int
    duplicates: int
    skipped: int
    alerts: List[AlertResponse] = []
    iocs_added: int = 0
    iocs_updated: int = 0
    alerts_rescored: int = 0
    summary: IngestSummary = IngestSummary()
    warnings: List[str] = []


class SampleFeed(BaseModel):
    name: str
    filename: str
    format: str
    source: str
    description: str
    payload: str


# ── Commander brief ───────────────────────────────────────────────────────────

class BriefPriority(BaseModel):
    rank: int
    alert_id: int
    timestamp: datetime
    priority: str
    risk_score: float
    verdict: str
    verdict_confidence: float
    event_type: str
    source_ip: str
    source: str
    asset: Optional[str] = None
    asset_criticality: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    is_attack_chain: bool = False
    bluf: AIExplanation


class BriefChain(BaseModel):
    source_ip: str
    alert_ids: List[int]
    alert_count: int
    assets: List[str] = []
    tactics: List[str] = []
    event_types: List[str] = []
    first_seen: datetime
    last_seen: datetime
    max_risk_score: float
    is_multi_stage: bool
    priority: str = "HIGH"
    genuine_count: int = 0
    bottom_line: str


class BriefSuppressed(BaseModel):
    alert_id: int
    event_type: str
    source_ip: str
    asset: Optional[str] = None
    priority: str
    verdict_confidence: float
    reason: str


class BriefStats(BaseModel):
    total_alerts: int
    open_alerts: int
    critical: int
    high: int
    genuine: int
    likely_false_positive: int
    needs_review: int
    attack_chains: int
    noise_reduction_pct: float
    sources: dict
    window_hours: int


class CommanderBrief(BaseModel):
    generated_at: datetime
    posture: str               # CRITICAL | ELEVATED | GUARDED | NORMAL
    bottom_line: str
    situation: str
    assessment: str
    recommendation: str
    stats: BriefStats
    attack_chains: List[BriefChain] = []
    priorities: List[BriefPriority] = []
    suppressed: List[BriefSuppressed] = []
    tactic_coverage: List[dict] = []   # [{tactic, count}] in kill-chain order
