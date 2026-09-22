"""
Threat Index aggregation engine.

Formula (capped at 100):
  Threat Index = min(100,
      (ai_confidence_score * 0.40)
    + payment_penalty          (0 or 30)
    + domain_penalty           (0, 10, 15, or 30)
    + process_bypass_penalty   (0 or 10)
  )
"""

from schemas import GeminiAnalysis, Flag, Severity


# ── Recommendation bank ────────────────────────────────────────────────────────
_RECS = {
    "payment":  "Never send money, gift cards, or cryptocurrency to a recruiter or landlord. "
                "Legitimate employers do not ask employees to purchase equipment personally and "
                "seek reimbursement.",
    "channel":  "Avoid conducting professional interviews exclusively over Telegram, WhatsApp, "
                "or Signal. Real companies use official video/phone systems and HR portals.",
    "domain":   "Verify the sender's email domain matches the company's official website. "
                "Cross-check on LinkedIn and call the company's published phone number directly.",
    "new_domain": "The sender domain was registered very recently. Fraudsters frequently create "
                  "lookalike domains days before launching a campaign.",
    "urgency":  "Pressure to sign immediately or accept within hours is a manipulation tactic. "
                "Authentic offer letters allow reasonable review time.",
    "generic":  "Do not provide personal or banking information until you have independently "
                "verified the organisation's legitimacy through official channels.",
}


def build_recommendations(
    ai: GeminiAnalysis,
    heuristics_penalty: int,
    domain_penalty: int,
    domain_age_days: int | None,
) -> list[str]:
    recs = []
    if ai.payment_demand_detected or heuristics_penalty >= 30:
        recs.append(_RECS["payment"])
    if ai.interview_bypass_detected or heuristics_penalty >= 60:
        recs.append(_RECS["channel"])
    if ai.free_email_domain_used or domain_penalty > 0:
        recs.append(_RECS["domain"])
    if domain_age_days is not None and domain_age_days < 90:
        recs.append(_RECS["new_domain"])
    if ai.urgency_detected:
        recs.append(_RECS["urgency"])
    if not recs:
        recs.append(_RECS["generic"])
    return recs


def compute_threat_index(
    ai: GeminiAnalysis,
    heuristics_penalty: int,
    domain_penalty: int,
) -> tuple[float, dict]:
    """
    Returns (threat_index, score_breakdown).

    Breakdown components
    --------------------
    ai_component          = ai_confidence_score * 0.40   (max 40)
    payment_penalty       = 30 if heuristics flagged payment keywords, else 0
    domain_penalty        = 0 / 10 / 15 / 30 from domain_checker
    process_bypass_penalty= 10 if interview_bypass_detected, else 0
    """
    ai_component           = round(ai.ai_confidence_score * 0.40, 2)
    process_bypass_penalty = 10 if ai.interview_bypass_detected else 0

    raw = ai_component + heuristics_penalty + domain_penalty + process_bypass_penalty
    threat_index = min(100.0, raw)

    breakdown = {
        "ai_component":           ai_component,
        "payment_penalty":        heuristics_penalty,
        "domain_penalty":         domain_penalty,
        "process_bypass_penalty": process_bypass_penalty,
        "raw_sum":                raw,
        "threat_index":           threat_index,
    }
    return threat_index, breakdown


def merge_flags(ai_flags: list[Flag], heuristic_findings: list[str]) -> list[Flag]:
    """Combine Gemini flags with heuristic text findings into a unified flag list."""
    merged = list(ai_flags)
    for finding in heuristic_findings:
        # Avoid duplicating flags already covered by Gemini
        if not any(f.evidence[:40].lower() in finding.lower() for f in ai_flags):
            merged.append(Flag(
                category="Heuristic Pattern",
                severity=Severity.HIGH,
                evidence=finding[:120],
            ))
    return merged
