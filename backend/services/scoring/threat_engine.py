"""
Threat Engine — single source of truth for scoring.

Formula (each capped at category max, total capped at 100):

  Financial / Payment Risk   = min(sum of payment signals,  25)
  Urgency / Coercion         = min(sum of urgency signals,  10)
  Recruitment Anomaly        = min(sum of recruit signals,  10)
  Email Provider Risk        = min(email provider score,    10)
  Organisation Mismatch      = min(sum of mismatch signals, 15)
  Domain Intelligence        = min(domain score,            15)
  URL Risk                   = min(sum of url signals,      10)
  AI Semantic Confirmation   = min(ai contribution,          5)
  Compound Risk Bonus        = min(bonus,                    5)  [only when 3+ categories significant]
  ──────────────────────────────────────────────────────────────
  TOTAL (Threat Index)       = min(raw_sum, 100)

Risk levels:
  0–24    LOW
  25–49   SUSPICIOUS
  50–74   HIGH
  75–100  CRITICAL
"""
from __future__ import annotations

from typing import Any, Optional

from schemas import (
    AIAnalysis,
    DomainIntelligence,
    RiskCategory,
    RiskLevel,
    RiskSignal,
    ScoreBreakdown,
)


# ── Recommendation bank (evidence-based, no absolutes) ────────────────────────
_RECS: dict[str, str] = {
    "payment": (
        "Sending money, cryptocurrency, gift cards, or wire transfers to a recruiter is a "
        "significant financial risk. Verify the employer's identity independently before taking "
        "any financial action."
    ),
    "fake_check": (
        "If you received a cheque or were told one is being sent, do NOT deposit it. "
        "In advance-fee and fake-check schemes, the bank may initially release funds before the "
        "cheque bounces — leaving you personally liable for the full amount."
    ),
    "channel": (
        "Recruitment conducted exclusively via informal messaging apps (Telegram, WhatsApp, Signal) "
        "without any verifiable corporate communication is a supporting risk indicator. "
        "Verify the employer's identity through their official website and published contact details."
    ),
    "domain": (
        "Verify the sender's email domain matches the company's official website. "
        "Cross-check on the company's official LinkedIn page and call their publicly listed number directly."
    ),
    "new_domain": (
        "The sender domain was registered very recently. This is a meaningful risk signal, as "
        "fraudsters frequently register look-alike domains shortly before launching phishing campaigns."
    ),
    "free_email": (
        "The sender is using a free consumer email provider (Gmail, Yahoo, etc.). "
        "Corporate recruitment is typically conducted from a company's own domain. "
        "This alone is not conclusive, but it is a relevant risk indicator — especially when combined with payment requests."
    ),
    "urgency": (
        "High-pressure tactics such as same-day deadlines or threats to withdraw an offer can be "
        "used to prevent careful verification. Take reasonable time to independently confirm the "
        "employer's identity before responding to any demands."
    ),
    "url": (
        "Do not click links in this document without first verifying the destination. "
        "URL shorteners and unencrypted (HTTP) links can redirect to sites designed to harvest credentials."
    ),
    "impersonation": (
        "The company name mentioned in the document does not appear to match the sender's email domain. "
        "Contact the referenced company directly through their official website to verify this offer."
    ),
    "generic": (
        "Do not provide personal or financial information until you have independently "
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

# Threshold to count a category as "significantly triggered" for compound bonus
_SIGNIFICANT_THRESHOLD = {
    RiskCategory.FINANCIAL:    12,
    RiskCategory.URGENCY:       5,
    RiskCategory.RECRUITMENT:   5,
    RiskCategory.EMAIL:         8,
    RiskCategory.ORG_MISMATCH:  8,
    RiskCategory.DOMAIN:        8,
    RiskCategory.URL:           4,
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


def _compound_bonus(cat_scores: dict[RiskCategory, int]) -> tuple[int, Optional[str]]:
    """
    Award a bounded compound-risk bonus when 3+ independent risk categories
    are simultaneously significant. The combination of, e.g., financial demands
    + urgency + recruitment anomaly is materially more indicative of the
    equipment-scam attack chain than any single factor alone.

    Bonus is capped at 5 pts and only applied once — no double-counting.
    """
    significant = [
        cat for cat, threshold in _SIGNIFICANT_THRESHOLD.items()
        if cat_scores.get(cat, 0) >= threshold
    ]
    if len(significant) >= 3:
        bonus = min(5, len(significant))
        cats_str = ", ".join(c.value.split("/")[0] for c in significant[:4])
        reason = (
            f"Compound risk: {len(significant)} major vectors simultaneously active "
            f"({cats_str})"
        )
        return bonus, reason
    return 0, None


def build_breakdown(
    all_signals:  list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> tuple[ScoreBreakdown, int, Optional[str]]:
    """
    Returns (ScoreBreakdown, compound_bonus, compound_reason).
    """
    fin  = _apply_cap(all_signals, RiskCategory.FINANCIAL)
    urg  = _apply_cap(all_signals, RiskCategory.URGENCY)
    rec  = _apply_cap(all_signals, RiskCategory.RECRUITMENT)
    eml  = _apply_cap(all_signals, RiskCategory.EMAIL)
    org  = min(_apply_cap(all_signals, RiskCategory.ORG_MISMATCH), 15)
    dom  = min(domain_intel.score_contribution if domain_intel else 0, 15)
    url  = _apply_cap(all_signals, RiskCategory.URL)
    ai   = min(ai_analysis.score_contribution, 5)

    cat_scores = {
        RiskCategory.FINANCIAL:    fin,
        RiskCategory.URGENCY:      urg,
        RiskCategory.RECRUITMENT:  rec,
        RiskCategory.EMAIL:        eml,
        RiskCategory.ORG_MISMATCH: org,
        RiskCategory.DOMAIN:       dom,
        RiskCategory.URL:          url,
    }
    compound, reason = _compound_bonus(cat_scores)

    raw   = fin + urg + rec + eml + org + dom + url + ai + compound
    total = float(min(100, raw))

    breakdown = ScoreBreakdown(
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
    return breakdown, compound, reason


def build_score_explanation(
    all_signals:   list[RiskSignal],
    domain_intel:  DomainIntelligence | None,
    ai_analysis:   AIAnalysis,
    breakdown:     ScoreBreakdown,
    compound:      int,
    compound_reason: Optional[str],
) -> dict[str, Any]:
    """
    Build a per-signal score trace for the 'Why this score?' UI panel.

    Structure:
    {
      "categories": {
        "Financial/Payment": {
          "signals": [{"label": "...", "points": 12}],
          "subtotal": 25, "cap": 25
        },
        ...
      },
      "compound_bonus": 3,
      "compound_reason": "...",
      "total": 48
    }
    """
    categories: dict[str, Any] = {}

    # Group signals by category
    for sig in all_signals:
        if sig.score_contribution <= 0:
            continue
        key = sig.category.value
        if key not in categories:
            categories[key] = {
                "signals": [],
                "subtotal": 0,
                "cap": _CAPS.get(sig.category, 0),
            }
        # Use first sentence of explanation as label
        label = sig.explanation.split(".")[0].strip()
        if len(label) > 70:
            label = label[:67] + "…"
        categories[key]["signals"].append({"label": label, "points": sig.score_contribution})
        categories[key]["subtotal"] += sig.score_contribution

    # Apply caps to subtotals in explanation view
    for key, data in categories.items():
        data["subtotal"] = min(data["subtotal"], data["cap"])

    # Domain intelligence
    if domain_intel and domain_intel.score_contribution > 0:
        key = RiskCategory.DOMAIN.value
        note = domain_intel.notes[0] if domain_intel.notes else "Domain registration risk"
        label = note.split(".")[0].strip()[:70]
        categories[key] = {
            "signals": [{"label": label, "points": domain_intel.score_contribution}],
            "subtotal": domain_intel.score_contribution,
            "cap": 15,
        }

    # AI semantic
    if ai_analysis.score_contribution > 0:
        key = RiskCategory.AI_SEMANTIC.value
        categories[key] = {
            "signals": [{
                "label": f"AI semantic analysis — {ai_analysis.confidence_score}% fraud confidence",
                "points": ai_analysis.score_contribution,
            }],
            "subtotal": ai_analysis.score_contribution,
            "cap": 5,
        }

    return {
        "categories": categories,
        "compound_bonus": compound,
        "compound_reason": compound_reason,
        "total": breakdown.total,
    }


def build_recommendations(
    all_signals:  list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> list[str]:
    recs: list[str] = []
    cats = {s.category for s in all_signals}

    if RiskCategory.FINANCIAL in cats:
        fake_check_found = any(
            "cheque" in s.evidence.lower() or "fake-check" in s.explanation.lower()
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
    risk_level = _risk_level(breakdown.total)

    if ai_analysis.available and ai_analysis.verdict_summary:
        return ai_analysis.verdict_summary

    if risk_level == RiskLevel.CRITICAL:
        return (
            "Strong indicators of fraud were detected across multiple independent risk categories. "
            "Exercise extreme caution — do not send money, share personal data, or sign any documents "
            "before independently verifying the sender's identity."
        )
    if risk_level == RiskLevel.HIGH:
        return (
            "Multiple high-risk patterns were identified in this document across several categories. "
            "Independently verify the sender's identity through official channels before taking any action."
        )
    if risk_level == RiskLevel.SUSPICIOUS:
        return (
            "Several suspicious patterns were detected that warrant further independent verification. "
            "Contact the referenced company directly through their official website before proceeding."
        )
    return (
        "No significant fraud indicators were detected in this document. "
        "Continue to exercise standard due diligence when evaluating any job offer."
    )


def compute_threat(
    all_signals:  list[RiskSignal],
    domain_intel: DomainIntelligence | None,
    ai_analysis:  AIAnalysis,
) -> tuple[float, RiskLevel, ScoreBreakdown, str, list[str], dict[str, Any]]:
    """
    Main entry point.

    Returns (threat_index, risk_level, breakdown, verdict_summary, recommendations, score_explanation).
    """
    breakdown, compound, compound_reason = build_breakdown(all_signals, domain_intel, ai_analysis)
    risk_level    = _risk_level(breakdown.total)
    verdict       = build_verdict(breakdown, ai_analysis)
    recs          = build_recommendations(all_signals, domain_intel, ai_analysis)
    explanation   = build_score_explanation(
        all_signals, domain_intel, ai_analysis, breakdown, compound, compound_reason
    )
    return breakdown.total, risk_level, breakdown, verdict, recs, explanation
