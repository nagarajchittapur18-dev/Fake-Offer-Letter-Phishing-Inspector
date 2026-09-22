from pydantic import BaseModel, Field
from typing import List, Optional
from enum import Enum


# ── Severity Levels ────────────────────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"


# ── Individual Flag (returned by Gemini + heuristics) ─────────────────────────
class Flag(BaseModel):
    category: str
    severity: Severity
    evidence: str


# ── Structured Gemini Analysis Output ─────────────────────────────────────────
class GeminiAnalysis(BaseModel):
    payment_demand_detected:   bool
    urgency_detected:          bool
    interview_bypass_detected: bool
    free_email_domain_used:    bool
    ai_confidence_score:       int = Field(..., ge=0, le=100)
    flags:                     List[Flag]
    verdict_summary:           str
    ai_audit_available:        bool = True


# ── API Request ────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    text: str
    url:  Optional[str] = None


# ── Domain Details (embedded in response) ─────────────────────────────────────
class DomainDetails(BaseModel):
    domain:        Optional[str]
    creation_date: Optional[str]
    age_in_days:   Optional[int]
    penalty:       int


# ── Full Scan API Response ─────────────────────────────────────────────────────
class ScanResponse(BaseModel):
    threat_index:            float          # 0-100
    verdict_summary:         str
    flags:                   List[Flag]
    domain_details:          Optional[DomainDetails]
    ai_analysis:             GeminiAnalysis
    safety_recommendations:  List[str]
    score_breakdown:         dict           # transparent score components
