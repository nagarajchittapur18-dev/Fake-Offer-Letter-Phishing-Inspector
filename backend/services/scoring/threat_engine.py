"""
Threat Engine — the single source of truth for scoring.

Formula (each capped at category max, total capped at 100):

  Financial / Payment Risk   = min(sum of payment signals,  25)
  Urgency / Coercion         = min(sum of urgency signals,  10)
  Recruitment Anomaly        = min(sum of recruit signals,  10)
  Email Provider Risk        = min(email provider score,    10)
  Organisation Mismatch      = min(sum of mismatch signals, 15)
  Domain Intelligence        = min(domain score,            15)
  URL Risk                   = min(sum of url signals,      10)
  AI Semantic Confirmation   = min(ai contribution,          5)
  ─────────────────────────────────────────────────────────────
  TOTAL (Threat Index)       = min(raw_sum, 100)

Risk levels:
  0–24    LOW
  25–49   SUSPICIOUS
  50–74   HIGH
  75–100  CRITICAL
"""
from __future__ import annotations

from schemas import (
    AIAnalysis,
    DomainIntelligence,
    RiskCategory,
    RiskLevel,
    RiskSignal,
    ScoreBreakdown,
    URLAnalysis,
)


# ── Context-aware recommendation bank ─────────────────────────────────────────
_RECS: dict[str, str] = {
    "payment": (
        "Never send money, cryptocurrency, gift cards, or wire transfers to a recruiter or landlord. "
        "Legitimate employers do not ask employees to purchase equipment personally and seek reimbursement."
    ),
    "fake_check": (
        "If you received a cheque, do NOT deposit it. Fake-check scams count on the bank releasing funds "
        "before the cheque bounces — leaving you liable for the full amount."
    ),
    "channel": (
        "Avoid conducting professional interviews exclusively over Telegram, WhatsApp, or Signal. "
        "Real companies use official video/phone systems and verifiable HR portals."
    ),
    "domain": (
        "Verify the sender's email domain matches the company's official website. "
        "Cross-check on LinkedIn and call the company's published phone number directly."
    ),
    "new_domain": (
        "The sender domain was registered very recently. Fraudsters frequently create "
        "lookalike domains days before launching a phishing campaign."
    ),
    "free_email": (
        "The sender is using a free consumer email address (Gmail, Yahoo, etc.). "
        "Legitimate organisations recruit from their own corporate email domain."
    ),
    "urgency": (
        "Pressure to sign immediately or accept within hours is a manipulation tactic. "
        "Authentic offer letters allow reasonable review time (typically 3–7 business days)."
    ),
    "url": (
        "Do not click links in this document without verifying the destination. "
        "URL shorteners and HTTP-only links can redirect to credential-harvesting pages."
    ),
    "impersonation": (
        "The company name in the document does not match the sender's email domain. "
        "Contact the real company through its official website to verify this offer."
    ),
    "generic": (
        "Do not provide personal or banking information until you have independently "
        "verified the organisation's legitimacy through official channels."
    ),
}


# ── Scoring caps per category ──────────────────────────────────────────────────
_CAPS = {
    RiskCategory.FINANCIAL:    25,
    RiskCategory.URGENCY:      10,
    RiskCategory.RECRUITMENT:  10,
    RiskCategory.EMAIL:        10,
    RiskCategory.ORG_MISMATCH: 15,
    RiskCategory.DOMAIN:       15,
    RiskCategory.URL:          10,
    RiskCategory.AI_SEMANTIC:   5,
}


def _risk_level(total: float) -> RiskLevel:
    if total >= 75:
        return RiskLevel.CRITICAL
    if total >= 50:
        return RiskLevel.HIGH
    if total >= 25:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.LOW


def _apply_cap(signals: list[RiskSignal], category: RiskCategory) -> int:
    """Sum score_contributions for a category, capped at its maximum."""
    raw = sum(s.score_contribution for s in signals if s.category == category)
    return min(raw, _CAPS[category])


def build_breakdown(
    all_signals: list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> ScoreBreakdown:
    fin  = _apply_cap(all_signals, RiskCategory.FINANCIAL)
    urg  = _apply_cap(all_signals, RiskCategory.URGENCY)
    rec  = _apply_cap(all_signals, RiskCategory.RECRUITMENT)
    eml  = _apply_cap(all_signals, RiskCategory.EMAIL)
    org  = min(_apply_cap(all_signals, RiskCategory.ORG_MISMATCH), 15)
    dom  = min(domain_intel.score_contribution if domain_intel else 0, 15)
    url  = _apply_cap(all_signals, RiskCategory.URL)
    ai   = min(ai_analysis.score_contribution, 5)

    total = float(min(100, fin + urg + rec + eml + org + dom + url + ai))

    return ScoreBreakdown(
        financial_payment=fin,
        urgency_coercion=urg,
        recruitment_anomaly=rec,
        email_provider=eml,
        org_mismatch=org,
        domain_intelligence=dom,
        url_risk=url,
        ai_semantic=ai,
        total=total,
    )


def build_recommendations(
    all_signals:  list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> list[str]:
    recs: list[str] = []
    cats = {s.category for s in all_signals}

    if RiskCategory.FINANCIAL in cats:
        # Check for fake-check specifically
        fake_check_found = any(
            "cheque" in s.evidence.lower() or "check" in s.evidence.lower() or "fake-check" in s.explanation.lower()
            for s in all_signals if s.category == RiskCategory.FINANCIAL
        )
        recs.append(_RECS["fake_check"] if fake_check_found else _RECS["payment"])

    if RiskCategory.RECRUITMENT in cats:
        recs.append(_RECS["channel"])

    if RiskCategory.EMAIL in cats:
        recs.append(_RECS["free_email"])

    if RiskCategory.ORG_MISMATCH in cats:
        recs.append(_RECS["impersonation"])

    if domain_intel and domain_intel.age_days is not None and domain_intel.age_days < 90:
        recs.append(_RECS["new_domain"])
    elif domain_intel and domain_intel.score_contribution > 0:
        recs.append(_RECS["domain"])

    if RiskCategory.URGENCY in cats:
        recs.append(_RECS["urgency"])

    if RiskCategory.URL in cats:
        recs.append(_RECS["url"])

    if not recs:
        recs.append(_RECS["generic"])

    return recs


def build_verdict(breakdown: ScoreBreakdown, ai_analysis: AIAnalysis) -> str:
    """Generate a neutral, evidence-based verdict summary."""
    risk_level = _risk_level(breakdown.total)

    if ai_analysis.available and ai_analysis.verdict_summary:
        return ai_analysis.verdict_summary

    if risk_level == RiskLevel.CRITICAL:
        return (
            "Strong indicators of fraud were detected across multiple risk categories. "
            "Exercise extreme caution — do not send money, share personal data, or sign any documents."
        )
    if risk_level == RiskLevel.HIGH:
        return (
            "Multiple high-risk patterns were identified in this document. "
            "Independently verify the sender's identity before taking any action."
        )
    if risk_level == RiskLevel.SUSPICIOUS:
        return (
            "Some suspicious patterns were found that warrant further verification. "
            "Contact the company directly through its official website before proceeding."
        )
    return (
        "No significant fraud indicators were detected in this document. "
        "Always exercise normal due diligence when responding to job offers."
    )


def compute_threat(
    all_signals:  list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> tuple[float, RiskLevel, ScoreBreakdown, str, list[str]]:
    """
    Main entry point.

    Returns (threat_index, risk_level, breakdown, verdict_summary, recommendations).
    """
    breakdown    = build_breakdown(all_signals, domain_intel, ai_analysis)
    risk_level   = _risk_level(breakdown.total)
    verdict      = build_verdict(breakdown, ai_analysis)
    recs         = build_recommendations(all_signals, domain_intel, ai_analysis)

    return breakdown.total, risk_level, breakdown, verdict, recs
