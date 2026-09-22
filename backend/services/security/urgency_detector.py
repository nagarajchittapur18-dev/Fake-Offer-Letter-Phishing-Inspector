"""
Urgency / coercion detector.

Identifies pressure tactics used to prevent victims from thinking critically.
Max contribution: 10 points.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from schemas import RiskCategory, RiskSignal, Severity


@dataclass
class _UrgencyPattern:
    name:        str
    patterns:    list[str]
    points:      int
    severity:    Severity
    explanation: str


_URGENCY_PATTERNS: list[_UrgencyPattern] = [
    _UrgencyPattern(
        name="24-hour / same-day deadline",
        patterns=[r"\bwithin\s+24\s+hours?\b", r"\bsame\s+day\b", r"\btoday\s+only\b",
                  r"\breply\s+(?:by|before)\s+(?:end\s+of\s+)?(?:day|today|tonight)\b"],
        points=6, severity=Severity.HIGH,
        explanation="Artificial 24-hour deadlines are a pressure tactic to prevent careful scrutiny.",
    ),
    _UrgencyPattern(
        name="Immediate confirmation required",
        patterns=[r"\bimmediately\b", r"\bimmediately\s+(?:confirm|accept|sign|respond)\b",
                  r"\bconfirm\s+(?:your\s+)?(?:acceptance\s+)?immediately\b",
                  r"\brespond\s+(?:urgently|immediately|asap|right\s+away)\b"],
        points=5, severity=Severity.MEDIUM,
        explanation="Demands for immediate confirmation prevent victims from doing due diligence.",
    ),
    _UrgencyPattern(
        name="Limited / final offer",
        patterns=[r"\blimited\s+(?:time\s+)?offer\b", r"\bfinal\s+offer\b", r"\blast\s+chance\b",
                  r"\bposition\s+will\s+(?:be\s+)?(?:filled|offered\s+to\s+someone\s+else)\b"],
        points=4, severity=Severity.MEDIUM,
        explanation="'Final offer' or 'position will be filled' creates false scarcity.",
    ),
    _UrgencyPattern(
        name="Do not share / keep confidential",
        patterns=[r"\bdo\s+not\s+(?:share|discuss|tell|disclose)\b", r"\bkeep\s+(?:this\s+)?confidential\b",
                  r"\bdo\s+not\s+contact\s+(?:the\s+)?(?:company|employer|HR)\b"],
        points=7, severity=Severity.HIGH,
        explanation="Instructing recipients not to verify independently is a key control mechanism in scams.",
    ),
    _UrgencyPattern(
        name="Threat of withdrawal",
        patterns=[r"\boffer\s+(?:will\s+be\s+)?(?:revoked|cancelled|withdrawn|void)\b",
                  r"\bif\s+(?:you\s+)?(?:don.t|do\s+not|fail\s+to)\s+(?:respond|reply|confirm|accept)\b"],
        points=5, severity=Severity.MEDIUM,
        explanation="Threatening to withdraw an offer is a manipulation tactic.",
    ),
    _UrgencyPattern(
        name="Secrecy / coercion",
        patterns=[r"\bsecret(?:ly)?\b", r"\bdo\s+not\s+let\s+(?:anyone|others)\s+know\b",
                  r"\bkeep\s+this\s+between\s+us\b"],
        points=6, severity=Severity.HIGH,
        explanation="Requests for secrecy about the job offer or payments are a key fraud indicator.",
    ),
]


def detect_urgency(text: str) -> list[RiskSignal]:
    """
    Return urgency/coercion RiskSignals. Total score_contribution capped at 10.
    """
    text_lower = text.lower()
    signals: list[RiskSignal] = []
    total_claimed = 0

    for pat in _URGENCY_PATTERNS:
        for regex in pat.patterns:
            match = re.search(regex, text_lower)
            if match:
                start   = max(0, match.start() - 30)
                end     = min(len(text), match.end() + 60)
                snippet = text[start:end].strip().replace("\n", " ")

                contrib = min(pat.points, 10 - total_claimed)
                if contrib <= 0:
                    break

                signals.append(RiskSignal(
                    category=RiskCategory.URGENCY,
                    severity=pat.severity,
                    score_contribution=contrib,
                    evidence=f'"{snippet}"',
                    explanation=pat.explanation,
                ))
                total_claimed += pat.points
                break

    return signals
