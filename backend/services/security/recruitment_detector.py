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
        explanation="Legitimate employers always conduct interviews. 'Immediate hire without interview' is a classic scam line.",
    ),
    _RecruitmentPattern(
        name="Informal contact channel",
        patterns=[
            r"\btelegram\b", r"\bwhatsapp\b", r"\bsignal\s+(?:app|messenger)?\b",
            r"\bcontact\s+(?:via|on|through)\s+(?:telegram|whatsapp|signal|text\s+only)\b",
        ],
        points=6, severity=Severity.HIGH,
        explanation="Conducting recruitment exclusively over Telegram, WhatsApp or Signal avoids auditable email trails.",
    ),
    _RecruitmentPattern(
        name="No experience / qualification required",
        patterns=[
            r"\bno\s+experience\s+(?:required|needed|necessary)\b",
            r"\bno\s+qualifications?\s+(?:required|needed)\b",
            r"\banyone\s+can\s+(?:apply|qualify|join)\b",
        ],
        points=4, severity=Severity.MEDIUM,
        explanation="Jobs requiring no experience offering high pay are a recruitment scam red flag.",
    ),
    _RecruitmentPattern(
        name="Unusually high salary for minimal work",
        patterns=[
            r"\b\$\s*(?:\d{3,})\s*(?:per\s+(?:day|hour|week))?\b.*(?:easy|simple|part.time|work\s+from\s+home)\b",
            r"\bearn\s+(?:up\s+to\s+)?\$\s*(?:\d{3,})\s+(?:per\s+(?:day|hour)|a\s+day|daily)\b",
        ],
        points=4, severity=Severity.MEDIUM,
        explanation="Promises of unusually high pay for simple/remote work are associated with scam job postings.",
    ),
    _RecruitmentPattern(
        name="Immediate personal information request",
        patterns=[
            r"\bprovide\s+(?:your\s+)?(?:social\s+security|SSN|passport\s+number|bank\s+account|routing\s+number)\b",
            r"\bsend\s+(?:us\s+)?(?:your\s+)?(?:ID|passport|driving\s+licence|national\s+ID)\s+(?:copy|scan|photo)\b",
        ],
        points=6, severity=Severity.HIGH,
        explanation="Requesting sensitive personal/financial information before formal onboarding is a phishing indicator.",
    ),
    _RecruitmentPattern(
        name="Vague company or role description",
        patterns=[
            r"\bdata\s+entry\s+(?:agent|specialist|operator)\b.*\bwork\s+from\s+home\b",
            r"\b(?:mystery\s+shopper|secret\s+shopper)\b",
            r"\bonline\s+(?:marketing\s+)?(?:agent|rep|representative)\s+(?:needed|wanted|required)\b",
        ],
        points=3, severity=Severity.LOW,
        explanation="Vague job titles like 'data entry agent' or 'mystery shopper' are frequently used in remote scams.",
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
