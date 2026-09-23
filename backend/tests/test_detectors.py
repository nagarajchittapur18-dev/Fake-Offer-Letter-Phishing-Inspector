"""
Security detector unit tests.
Tests all 4 security detectors + email analyzer + threat engine.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from schemas import RiskCategory, RiskLevel
from services.security.payment_detector import detect_payment_risk
from services.security.urgency_detector import detect_urgency
from services.security.recruitment_detector import detect_recruitment_anomalies
from services.security.impersonation_detector import detect_impersonation
from services.security.email_analyzer import (
    classify_email_domain,
    detect_email_provider_risk,
    detect_reply_to_mismatch,
    FREE_EMAIL_PROVIDERS,
)
from services.scoring.threat_engine import compute_threat, _risk_level
from services.ai.gemini_analyzer import AIAnalysis


# ── Payment detector ───────────────────────────────────────────────────────────

def test_payment_detects_check():
    text = "We will send you a check for equipment purchase reimbursement."
    signals = detect_payment_risk(text)
    assert len(signals) > 0
    assert all(s.category == RiskCategory.FINANCIAL for s in signals)

def test_payment_detects_wire_transfer():
    signals = detect_payment_risk("Please wire transfer the funds immediately.")
    assert any("wire" in s.evidence.lower() or s.score_contribution > 0 for s in signals)

def test_payment_detects_crypto():
    signals = detect_payment_risk("Send 0.5 BTC to our bitcoin wallet address.")
    assert len(signals) > 0

def test_payment_detects_gift_card():
    signals = detect_payment_risk("Please purchase a $500 Google Play gift card.")
    assert len(signals) > 0

def test_payment_score_capped_at_25():
    # Even if many patterns fire, total contribution should not exceed 25
    text = (
        "Send a wire transfer for equipment purchase reimbursement. "
        "Pay with bitcoin or gift card. Western Union also accepted. "
        "Processing fee required. Background check fee applies."
    )
    signals = detect_payment_risk(text)
    total = sum(s.score_contribution for s in signals)
    assert total <= 25

def test_payment_clean_text():
    signals = detect_payment_risk("We are pleased to offer you the position of Software Engineer.")
    assert len(signals) == 0


# ── Urgency detector ───────────────────────────────────────────────────────────

def test_urgency_detects_24h_deadline():
    signals = detect_urgency("Please confirm your acceptance within 24 hours or the offer will be revoked.")
    assert len(signals) > 0

def test_urgency_detects_confidentiality():
    signals = detect_urgency("Keep this job offer confidential. Do not share with anyone.")
    assert len(signals) > 0

def test_urgency_score_capped_at_10():
    text = (
        "Confirm immediately. Do not share. Limited time offer. "
        "Reply within 24 hours or your offer will be revoked and cancelled."
    )
    signals = detect_urgency(text)
    total = sum(s.score_contribution for s in signals)
    assert total <= 10

def test_urgency_clean_text():
    text = "We look forward to you joining the team. Please let us know by next Friday."
    assert len(detect_urgency(text)) == 0


# ── Recruitment detector ───────────────────────────────────────────────────────

def test_recruitment_detects_no_interview():
    signals = detect_recruitment_anomalies("You have been hired without an interview.")
    assert len(signals) > 0

def test_recruitment_detects_telegram():
    signals = detect_recruitment_anomalies("Contact our HR team on Telegram to proceed.")
    assert len(signals) > 0

def test_recruitment_detects_no_experience():
    signals = detect_recruitment_anomalies("No experience required. Apply now!")
    assert len(signals) > 0

def test_recruitment_score_capped_at_10():
    text = (
        "Immediate hire without interview. No experience required. "
        "Contact via Telegram or WhatsApp. Provide your SSN and passport scan."
    )
    signals = detect_recruitment_anomalies(text)
    total = sum(s.score_contribution for s in signals)
    assert total <= 10


# ── Email analyzer ─────────────────────────────────────────────────────────────

def test_classify_gmail_as_free():
    ptype, score, _ = classify_email_domain("gmail.com")
    assert ptype == "Free Email Provider"
    assert score == 10

def test_classify_corporate_as_corporate():
    ptype, score, _ = classify_email_domain("microsoft.com")
    assert ptype == "Corporate Domain"
    assert score == 0

def test_free_email_domains_list_coverage():
    for d in ["yahoo.com", "hotmail.com", "protonmail.com", "icloud.com"]:
        assert d in FREE_EMAIL_PROVIDERS

def test_detect_email_provider_risk_gmail():
    signals = detect_email_provider_risk("gmail.com")
    assert len(signals) == 1
    assert signals[0].score_contribution == 10

def test_detect_reply_to_mismatch():
    signals = detect_reply_to_mismatch("company.com", "gmail.com")
    assert len(signals) == 1

def test_no_reply_to_mismatch_same_domain():
    signals = detect_reply_to_mismatch("company.com", "company.com")
    assert len(signals) == 0


# ── Impersonation detector ─────────────────────────────────────────────────────

def test_impersonation_mismatch_detected():
    text   = "On behalf of Microsoft Corporation, welcome to the team."
    signals = detect_impersonation(text, "gmail.com")
    # gmail.com is a free provider so this should be caught by email_analyzer, not impersonation
    # Test with a corporate domain mismatch
    signals = detect_impersonation(text, "fake-recruiter.xyz")
    assert len(signals) > 0

def test_impersonation_no_sender():
    text    = "On behalf of Apple Inc, welcome."
    signals = detect_impersonation(text, None)
    assert len(signals) == 0


# ── Threat engine ──────────────────────────────────────────────────────────────

def test_risk_level_boundaries():
    assert _risk_level(0)   == RiskLevel.LOW
    assert _risk_level(24)  == RiskLevel.LOW
    assert _risk_level(25)  == RiskLevel.SUSPICIOUS
    assert _risk_level(49)  == RiskLevel.SUSPICIOUS
    assert _risk_level(50)  == RiskLevel.HIGH
    assert _risk_level(74)  == RiskLevel.HIGH
    assert _risk_level(75)  == RiskLevel.CRITICAL
    assert _risk_level(100) == RiskLevel.CRITICAL

def test_compute_threat_returns_valid_structure():
    ai = AIAnalysis(
        available=False, confidence_score=0, score_contribution=0,
        verdict_summary="Test", semantic_flags=[],
    )
    payment_sigs = detect_payment_risk("Send a wire transfer for equipment purchase.")
    threat_index, risk_level, breakdown, verdict, recs, explanation = compute_threat(
        payment_sigs, None, ai
    )
    assert 0 <= threat_index <= 100
    assert breakdown.total == threat_index
    assert len(recs) > 0
    # score_explanation must be a dict
    assert isinstance(explanation, dict)
    assert "categories" in explanation
    assert "total" in explanation

def test_compute_threat_high_risk_scam():
    ai = AIAnalysis(
        available=True, model="gemini-2.0-flash",
        confidence_score=90, score_contribution=5,
        verdict_summary="High risk of fraud.", semantic_flags=["payment scam"],
    )
    text = (
        "Congratulations! You have been hired without interview on Telegram. "
        "Send a wire transfer for equipment. Reply within 24 hours. "
        "Do not discuss this offer with anyone."
    )
    all_signals = (
        detect_payment_risk(text)
        + detect_urgency(text)
        + detect_recruitment_anomalies(text)
        + detect_email_provider_risk("gmail.com")
    )
    threat_index, risk_level, breakdown, verdict, recs, explanation = compute_threat(
        all_signals, None, ai
    )
    assert threat_index >= 25  # Must at least reach SUSPICIOUS
    assert risk_level in (RiskLevel.SUSPICIOUS, RiskLevel.HIGH, RiskLevel.CRITICAL)

def test_compute_threat_clean_text():
    ai = AIAnalysis(
        available=True, model="gemini-2.0-flash",
        confidence_score=5, score_contribution=0,
        verdict_summary="No fraud indicators.", semantic_flags=[],
    )
    text = "We are pleased to offer you the role of Software Engineer at a salary of $80,000."
    all_signals = (
        detect_payment_risk(text)
        + detect_urgency(text)
        + detect_recruitment_anomalies(text)
    )
    threat_index, risk_level, breakdown, verdict, recs, explanation = compute_threat(
        all_signals, None, ai
    )
    assert risk_level == RiskLevel.LOW

def test_compound_bonus_triggers_with_3_categories():
    """When Financial + Urgency + Recruitment are all significantly triggered,
    a compound bonus should be added to the total score."""
    ai = AIAnalysis(
        available=False, confidence_score=0, score_contribution=0,
        verdict_summary="N/A", semantic_flags=[],
    )
    text = (
        "You are hired without interview. Wire transfer $500 for equipment. "
        "Confirm within 24 hours. Do not discuss this with anyone."
    )
    all_signals = (
        detect_payment_risk(text)
        + detect_urgency(text)
        + detect_recruitment_anomalies(text)
    )
    _, _, breakdown, _, _, explanation = compute_threat(all_signals, None, ai)
    # compound_bonus in explanation should be >= 0
    assert explanation["compound_bonus"] >= 0
    # If 3+ significant categories, compound_bonus should be > 0
    cat_scores = {
        "Financial": breakdown.financial_payment,
        "Urgency": breakdown.urgency_coercion,
        "Recruitment": breakdown.recruitment_anomaly,
    }
    multi_significant = sum(1 for v in cat_scores.values() if v >= 5)
    if multi_significant >= 3:
        assert explanation["compound_bonus"] > 0

def test_score_explanation_structure():
    """score_explanation must have categories, compound_bonus, total keys."""
    ai = AIAnalysis(
        available=False, confidence_score=0, score_contribution=0,
        verdict_summary="N/A", semantic_flags=[],
    )
    signals = detect_payment_risk("Please wire transfer funds for equipment purchase reimbursement.")
    _, _, _, _, _, expl = compute_threat(signals, None, ai)
    assert "categories" in expl
    assert "compound_bonus" in expl
    assert "total" in expl
    assert isinstance(expl["compound_bonus"], int)
    # Financial category should appear in explanation
    assert "Financial/Payment" in expl["categories"]

def test_ai_unavailable_fallback():
    """When AI is unavailable, score_contribution must be 0 and verdict uses heuristic."""
    ai = AIAnalysis(
        available=False, confidence_score=0, score_contribution=0,
        verdict_summary="AI unavailable", semantic_flags=[],
    )
    signals = detect_urgency("Please confirm immediately — offer will be revoked within 24 hours.")
    _, _, breakdown, verdict, _, _ = compute_threat(signals, None, ai)
    assert breakdown.ai_semantic == 0
    # Verdict must be heuristic-generated (not from AI)
    assert len(verdict) > 10

def test_email_provider_distinct_from_domain_age():
    """Gmail classification should NOT be confused with domain age.
    Free email provider check and domain age are separate risk signals."""
    from services.security.email_analyzer import classify_email_domain
    # Gmail is a free email provider (high risk signal)
    ptype, score, explanation = classify_email_domain("gmail.com")
    assert ptype == "Free Email Provider"
    assert score == 10
    # Corporate domain should score 0 for email provider check
    ptype2, score2, _ = classify_email_domain("amazon.com")
    assert ptype2 == "Corporate Domain"
    assert score2 == 0

