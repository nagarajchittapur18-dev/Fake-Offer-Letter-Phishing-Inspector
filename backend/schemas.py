"""
V2 Pydantic schemas — all API request and response models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── Enumerations ───────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"


class RiskCategory(str, Enum):
    FINANCIAL    = "Financial/Payment"
    URGENCY      = "Urgency/Coercion"
    RECRUITMENT  = "Recruitment Anomaly"
    EMAIL        = "Email Provider"
    ORG_MISMATCH = "Organization Mismatch"
    DOMAIN       = "Domain Intelligence"
    URL          = "URL Risk"
    AI_SEMANTIC  = "AI Semantic"


class RiskLevel(str, Enum):
    LOW        = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH       = "HIGH"
    CRITICAL   = "CRITICAL"


class InputType(str, Enum):
    TEXT = "text"
    FILE = "file"
    URL  = "url"


# ── Request bodies ─────────────────────────────────────────────────────────────

class ScanTextRequest(BaseModel):
    text:         str            = Field(..., min_length=10, max_length=50_000)
    sender_email: Optional[str] = Field(None, description="Optional sender email for mismatch analysis")
    url:          Optional[str] = Field(None, description="Optional URL to also analyse")


class ScanURLRequest(BaseModel):
    url: str = Field(..., min_length=4)


# ── Risk signal (one per detected issue) ──────────────────────────────────────

class RiskSignal(BaseModel):
    category:           RiskCategory
    severity:           Severity
    score_contribution: int   = Field(..., ge=0, le=25, description="Points this signal adds to total (capped at category max)")
    evidence:           str   = Field(..., description="Verbatim quote or extracted value that triggered this signal")
    explanation:        str   = Field(..., description="Plain-English explanation of why this is suspicious")


# ── Domain intelligence ────────────────────────────────────────────────────────

class DomainIntelligence(BaseModel):
    domain:             Optional[str]
    age_days:           Optional[int]
    created:            Optional[str]
    provider_type:      str   = Field(..., description="Free Email Provider | Corporate | New Domain | Unknown")
    registrar:          Optional[str] = None
    score_contribution: int   = Field(..., ge=0, le=15)
    notes:              List[str] = []


# ── URL analysis ───────────────────────────────────────────────────────────────

class URLAnalysis(BaseModel):
    url:                str
    is_reachable:       bool
    is_suspicious:      bool
    is_ssrf_blocked:    bool
    final_url:          Optional[str] = None
    status_code:        Optional[int] = None
    redirect_count:     int = 0
    score_contribution: int = Field(..., ge=0, le=10)
    evidence:           str


# ── AI analysis ────────────────────────────────────────────────────────────────

class AIAnalysis(BaseModel):
    available:          bool
    model:              Optional[str] = None
    confidence_score:   int  = Field(0, ge=0, le=100)
    score_contribution: int  = Field(0, ge=0, le=5)
    verdict_summary:    str
    semantic_flags:     List[str] = []


# ── Score breakdown (per-category, max shown next to each) ────────────────────

class ScoreBreakdown(BaseModel):
    financial_payment:   int = Field(0, ge=0, le=25, description="max 25")
    urgency_coercion:    int = Field(0, ge=0, le=10, description="max 10")
    recruitment_anomaly: int = Field(0, ge=0, le=10, description="max 10")
    email_provider:      int = Field(0, ge=0, le=10, description="max 10")
    org_mismatch:        int = Field(0, ge=0, le=15, description="max 15")
    domain_intelligence: int = Field(0, ge=0, le=15, description="max 15")
    url_risk:            int = Field(0, ge=0, le=10, description="max 10")
    ai_semantic:         int = Field(0, ge=0, le=5,  description="max 5")
    total:               float


# ── Full scan response ─────────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    scan_id:             str
    threat_index:        float          = Field(..., ge=0.0, le=100.0)
    risk_level:          RiskLevel
    verdict_summary:     str
    risk_signals:        List[RiskSignal]
    score_breakdown:     ScoreBreakdown
    score_explanation:   Dict[str, Any]  = Field(default_factory=dict,
                             description="Per-signal score trace for 'Why this score?' UI")
    domain_intelligence: Optional[DomainIntelligence] = None
    url_analyses:        List[URLAnalysis] = []
    ai_analysis:         AIAnalysis
    recommendations:     List[str]
    metadata:            Dict[str, Any] = {}
    input_type:          InputType
    scanned_at:          str


# ── Scan history ───────────────────────────────────────────────────────────────

class ScanHistoryItem(BaseModel):
    scan_id:     str
    created_at:  str
    input_type:  str
    source_name: Optional[str] = None
    domain:      Optional[str] = None
    threat_index: float
    risk_level:  RiskLevel
    signal_count: int = 0


# ── Health check ───────────────────────────────────────────────────────────────

class ComponentStatus(BaseModel):
    status:  str   # "online" | "degraded" | "offline"
    message: str


class HealthResponse(BaseModel):
    status:     str    # "healthy" | "degraded" | "unhealthy"
    version:    str = "2.0.0"
    components: Dict[str, ComponentStatus]
    timestamp:  str


def new_scan_id() -> str:
    return str(uuid.uuid4())


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
