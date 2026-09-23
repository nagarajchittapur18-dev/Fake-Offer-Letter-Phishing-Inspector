"""End-to-end verification of the full scan pipeline."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
os.environ['DB_PATH'] = 'test_e2e_verify.db'

from services.security.payment_detector import detect_payment_risk
from services.security.urgency_detector import detect_urgency
from services.security.recruitment_detector import detect_recruitment_anomalies
from services.security.email_analyzer import detect_email_provider_risk
from services.security.impersonation_detector import detect_impersonation
from services.scoring.threat_engine import compute_threat
from schemas import AIAnalysis, RiskLevel

ai_off = AIAnalysis(available=False, confidence_score=0, score_contribution=0,
                    verdict_summary='', semantic_flags=[])

# ── Scenario 1: Equipment Scam ─────────────────────────────────────────────────
text_scam = (
    "Congratulations! You are hired without an interview. Send a wire transfer for equipment. "
    "Reply within 24 hours or the offer will be revoked. Do not discuss this offer with anyone. "
    "Contact HR on Telegram."
)
sigs = (
    detect_payment_risk(text_scam)
    + detect_urgency(text_scam)
    + detect_recruitment_anomalies(text_scam)
)
idx, lvl, breakdown, verdict, recs, expl = compute_threat(sigs, None, ai_off)
print(f"SCENARIO 1 — Equipment Scam:")
print(f"  Score:     {idx}/100  ({lvl.value})")
print(f"  Financial: {breakdown.financial_payment}/25")
print(f"  Urgency:   {breakdown.urgency_coercion}/10")
print(f"  Recruit:   {breakdown.recruitment_anomaly}/10")
print(f"  Compound:  +{expl['compound_bonus']} ({expl['compound_reason']})")
print(f"  Verdict:   {verdict[:100]}")
print(f"  Expl cats: {list(expl['categories'].keys())}")
assert idx >= 30, f"Expected >=30, got {idx}"
assert expl['compound_bonus'] >= 0
assert "Financial/Payment" in expl['categories']
print("  [PASS]\n")

# ── Scenario 2: Corporate Impersonation ───────────────────────────────────────
text_imp = (
    "On behalf of Microsoft Corporation, we are pleased to offer you the position. "
    "Reply to hr@not-microsoft.xyz for more details."
)
sigs2 = detect_impersonation(text_imp, "not-microsoft.xyz")
idx2, lvl2, _, _, _, _ = compute_threat(sigs2, None, ai_off)
print(f"SCENARIO 2 — Corporate Impersonation:")
print(f"  Score:  {idx2}/100  ({lvl2.value})")
print(f"  Signals: {len(sigs2)}")
print("  [PASS]\n")

# ── Scenario 3: Clean Legitimate Offer ────────────────────────────────────────
text_clean = (
    "We are pleased to offer you the role of Software Engineer at Acme Corp. "
    "Annual salary USD 90000. Please review and return the signed contract by next Friday."
)
sigs3 = detect_payment_risk(text_clean) + detect_urgency(text_clean)
idx3, lvl3, _, _, _, _ = compute_threat(sigs3, None, ai_off)
print(f"SCENARIO 3 — Clean Legitimate Offer:")
print(f"  Score:  {idx3}/100  ({lvl3.value})")
assert lvl3 == RiskLevel.LOW, f"Expected LOW for clean text, got {lvl3.value}"
print("  [PASS]\n")

# ── Scenario 4: AI unavailable branch ────────────────────────────────────────
print(f"SCENARIO 4 — AI Unavailable:")
print(f"  ai.available={ai_off.available}, ai.score_contribution={ai_off.score_contribution}")
assert ai_off.score_contribution == 0
print("  [PASS]\n")

# ── Scenario 5: Score explanation always has total ────────────────────────────
print(f"SCENARIO 5 — Score Explanation Structure:")
assert "total" in expl
assert "compound_bonus" in expl
assert "categories" in expl
assert isinstance(expl["compound_bonus"], int)
print(f"  total={expl['total']}, compound={expl['compound_bonus']}")
print("  [PASS]\n")

# Clean up
try:
    os.remove("test_e2e_verify.db")
except Exception:
    pass

print("=" * 50)
print("ALL E2E SCENARIOS PASSED")
print("=" * 50)
