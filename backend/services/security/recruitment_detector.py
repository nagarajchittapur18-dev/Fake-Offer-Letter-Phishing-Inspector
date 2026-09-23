"""
Recruitment anomaly detector.

Identifies patterns that signal fraudulent job offers:
  • Interview bypass / guaranteed hire
  • Informal channels (Telegram, WhatsApp, Signal)
  • Excessive perks with no experience required
  • Vague job description
  • Asking for personal data immediately

Max contribution: 10 points.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from schemas import RiskCategory, RiskSignal, Severity


@dataclass
class _RecruitmentPattern:
    name:        str
    patterns:    list[str]
    points:      int
    severity:    Severity
    explanation: str


_RECRUITMENT_PATTERNS: list[_RecruitmentPattern] = [
    _RecruitmentPattern(
        name="Interview bypass / guaranteed hire",
        patterns=[
            r"\bwithout\s+(?:an?\s+)?interview\b",
            r"\bno\s+interview\s+(?:required|needed)\b",
            r"\bimmediate(?:ly)?\s+(?:hired|hire|employed|selected)\b",
            r"\byou(?:\s+are|\s+'re|\s+have\s+been)\s+(?:already\s+)?(?:hired|selected|chosen)\s+without\b",
            r"\bguaranteed\s+(?:job|position|employment|hire)\b",
        ],
        points=8, severity=Severity.HIGH,
        explanation=(
            "An immediate job offer without a standard interview or verification process "
            "is a significant recruitment-risk indicator, particularly when combined with "
            "payment requests or urgency pressure."
        ),
    ),
    _RecruitmentPattern(
        name="Informal contact channel",
        patterns=[
            r"\btelegram\b", r"\bwhatsapp\b", r"\bsignal\s+(?:app|messenger)?\b",
            r"\bcontact\s+(?:via|on|through)\s+(?:telegram|whatsapp|signal|text\s+only)\b",
        ],
        points=6, severity=Severity.HIGH,
        explanation=(
            "Conducting recruitment exclusively via informal messaging apps (Telegram, WhatsApp, Signal) "
            "without any verifiable corporate communication is a supporting risk indicator. "
            "Legitimate organisations typically use auditable, official contact channels."
        ),
    ),
    _RecruitmentPattern(
        name="No experience / qualification required",
        patterns=[
            r"\bno\s+experience\s+(?:required|needed|necessary)\b",
            r"\bno\s+qualifications?\s+(?:required|needed)\b",
            r"\banyone\s+can\s+(?:apply|qualify|join)\b",
        ],
        points=4, severity=Severity.MEDIUM,
        explanation=(
            "A high-paying role advertised with no experience or qualifications required "
            "is a common pattern in fraudulent remote-work postings."
        ),
    ),
    _RecruitmentPattern(
        name="Unusually high salary for minimal work",
        patterns=[
            r"\b\$\s*(?:\d{3,})\s*(?:per\s+(?:day|hour|week))?\b.*(?:easy|simple|part.time|work\s+from\s+home)\b",
            r"\bearn\s+(?:up\s+to\s+)?\$\s*(?:\d{3,})\s+(?:per\s+(?:day|hour)|a\s+day|daily)\b",
        ],
        points=4, severity=Severity.MEDIUM,
        explanation=(
            "Promises of very high pay for simple or part-time remote work are frequently "
            "associated with scam job postings. Verify the role and salary against industry benchmarks."
        ),
    ),
    _RecruitmentPattern(
        name="Immediate personal information request",
        patterns=[
            r"\bprovide\s+(?:your\s+)?(?:social\s+security|SSN|passport\s+number|bank\s+account|routing\s+number)\b",
            r"\bsend\s+(?:us\s+)?(?:your\s+)?(?:ID|passport|driving\s+licence|national\s+ID)\s+(?:copy|scan|photo)\b",
        ],
        points=6, severity=Severity.HIGH,
        explanation=(
            "Requesting sensitive personal or financial information early in an unsolicited "
            "recruitment process — before formal onboarding — is a phishing indicator."
        ),
    ),
    _RecruitmentPattern(
        name="Vague company or role description",
        patterns=[
            r"\bdata\s+entry\s+(?:agent|specialist|operator)\b.*\bwork\s+from\s+home\b",
            r"\b(?:mystery\s+shopper|secret\s+shopper)\b",
            r"\bonline\s+(?:marketing\s+)?(?:agent|rep|representative)\s+(?:needed|wanted|required)\b",
        ],
        points=3, severity=Severity.LOW,
        explanation=(
            "Vague or generic job titles (e.g., 'data entry agent', 'mystery shopper') "
            "without a named employer are commonly used in remote-work fraud schemes."
        ),
    ),
]


def detect_recruitment_anomalies(text: str) -> list[RiskSignal]:
    """Return recruitment-anomaly RiskSignals. Total score_contribution capped at 10."""
    text_lower = text.lower()
    signals: list[RiskSignal] = []
    total_claimed = 0

    for pat in _RECRUITMENT_PATTERNS:
        for regex in pat.patterns:
            match = re.search(regex, text_lower)
            if match:
                start   = max(0, match.start() - 30)
                end     = min(len(text), match.end() + 80)
                snippet = text[start:end].strip().replace("\n", " ")

                contrib = min(pat.points, 10 - total_claimed)
                if contrib <= 0:
                    break

                signals.append(RiskSignal(
                    category=RiskCategory.RECRUITMENT,
                    severity=pat.severity,
                    score_contribution=contrib,
                    evidence=f'"{snippet}"',
                    explanation=pat.explanation,
                ))
                total_claimed += pat.points
                break

    return signals
