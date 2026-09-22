"""
Financial / Payment risk detector.

Scores text for 19 categories of payment scam patterns.
Returns a list of RiskSignal objects for matching patterns.

Max contribution: 25 points (capped).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from schemas import RiskCategory, RiskSignal, Severity


# ── Payment signal definitions ─────────────────────────────────────────────────
@dataclass
class _PaymentPattern:
    name:        str
    patterns:    list[str]   # regex patterns
    points:      int         # score contribution of this pattern
    severity:    Severity
    explanation: str


_PATTERNS: list[_PaymentPattern] = [
    _PaymentPattern(
        name="Fake-check scam",
        patterns=[r"\bfake\s+check\b", r"\bsend\s+(?:you\s+a\s+)?check\b", r"\bcheque\s+(?:will\s+be\s+)?(?:sent|mailed|issued)\b"],
        points=15, severity=Severity.CRITICAL,
        explanation="Sending a cheque/check to a new hire to buy equipment is the textbook 'fake-check' advance-fee scam.",
    ),
    _PaymentPattern(
        name="Equipment purchase demand",
        patterns=[r"\bequipment\s+(?:purchase|buy|order)\b", r"\bpurchase\s+(?:equipment|laptop|computer|tools)\b",
                  r"\bbuy\s+(?:your\s+own\s+)?(?:equipment|laptop|supplies)\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Asking a new hire to purchase work equipment with their own money is a standard scam vector.",
    ),
    _PaymentPattern(
        name="Wire transfer / bank transfer",
        patterns=[r"\bwire\s+transfer\b", r"\bbank\s+transfer\b", r"\btransfer\s+(?:the\s+)?(?:funds|money|amount|balance)\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Wire transfers are irreversible and strongly preferred by scammers.",
    ),
    _PaymentPattern(
        name="Reimbursement-then-forward scheme",
        patterns=[r"\breimburs(?:e|ement|ed)\b", r"\bforward\s+(?:the\s+)?(?:balance|remaining|rest|excess)\b",
                  r"\bsend\s+(?:back|the\s+change|the\s+remainder)\b"],
        points=10, severity=Severity.HIGH,
        explanation="'Buy and get reimbursed' or 'forward the balance' is the key mechanism of the equipment-purchase scam.",
    ),
    _PaymentPattern(
        name="Cryptocurrency payment",
        patterns=[r"\bcrypto(?:currency)?\b", r"\bbitcoin\b", r"\bethererum\b", r"\busdt\b", r"\bwallet\s+address\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Requesting cryptocurrency payment is a strong scam indicator — impossible to reverse.",
    ),
    _PaymentPattern(
        name="Gift card / prepaid card",
        patterns=[r"\bgift\s+card\b", r"\bgoogle\s+play\s+(?:card|gift)\b", r"\bamazon\s+gift\b",
                  r"\bitunes\s+card\b", r"\bsteam\s+card\b", r"\bprepaid\s+(?:card|debit)\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Gift card payment requests are used exclusively by scammers — no legitimate employer does this.",
    ),
    _PaymentPattern(
        name="Western Union / MoneyGram",
        patterns=[r"\bwestern\s+union\b", r"\bmoneygram\b", r"\bmoney\s+order\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Western Union and MoneyGram are cash-based, irreversible, and heavily used in scams.",
    ),
    _PaymentPattern(
        name="Zelle / CashApp / Venmo",
        patterns=[r"\bzelle\b", r"\bcashapp\b", r"\bcash\s+app\b", r"\bvenmo\b", r"\bpaypal\.me\b"],
        points=10, severity=Severity.HIGH,
        explanation="P2P payment apps lack fraud protection and are used in employment scams.",
    ),
    _PaymentPattern(
        name="Processing / admin fee",
        patterns=[r"\bprocessing\s+fee\b", r"\badmin(?:istration)?\s+fee\b", r"\bregistration\s+fee\b",
                  r"\bactivation\s+fee\b", r"\bapplication\s+fee\b"],
        points=10, severity=Severity.HIGH,
        explanation="Legitimate employers never charge processing or registration fees.",
    ),
    _PaymentPattern(
        name="Background check fee (upfront)",
        patterns=[r"\bbackground\s+check\s+fee\b", r"\bpay\s+for\s+(?:your\s+)?background\b",
                  r"\bbackground\s+screening\s+cost\b"],
        points=10, severity=Severity.HIGH,
        explanation="If a real background check is required, the employer pays for it.",
    ),
    _PaymentPattern(
        name="Training / orientation fee",
        patterns=[r"\btraining\s+fee\b", r"\borientation\s+fee\b", r"\btraining\s+materials?\s+cost\b"],
        points=8, severity=Severity.HIGH,
        explanation="Charging a fee for training materials before employment is a common recruitment scam.",
    ),
    _PaymentPattern(
        name="Security deposit (rental scam)",
        patterns=[r"\bsecurity\s+deposit\b", r"\brent\s+deposit\b", r"\bdeposit\s+before\s+(?:viewing|moving|visit)\b"],
        points=10, severity=Severity.HIGH,
        explanation="Requiring a deposit before property viewing is the classic rental phishing pattern.",
    ),
    _PaymentPattern(
        name="Pay advance / prepayment",
        patterns=[r"\bpay\s+in\s+advance\b", r"\bprepayment\s+required\b", r"\badvance\s+payment\b"],
        points=8, severity=Severity.MEDIUM,
        explanation="Advance payments to strangers online are a common fraud mechanism.",
    ),
    _PaymentPattern(
        name="Money laundering indicators",
        patterns=[r"\bforward\s+(?:the\s+)?(?:money|funds|payment)\b", r"\bact\s+as\s+(?:a\s+)?(?:money|payment)\s+agent\b",
                  r"\bprocess\s+(?:payments?|transactions?)\s+on\s+(?:our|my)\s+behalf\b"],
        points=15, severity=Severity.CRITICAL,
        explanation="Forwarding money on behalf of an unknown party is a money-mule operation.",
    ),
    _PaymentPattern(
        name="Overpayment trap",
        patterns=[r"\boverpay(?:ment)?\b", r"\bextra\s+amount\b", r"\baccidentally\s+(?:sent|transferred)\s+(?:too\s+much|extra)\b"],
        points=12, severity=Severity.CRITICAL,
        explanation="Overpayment followed by 'please return the difference' is a classic fraud variant.",
    ),
]


def detect_payment_risk(text: str) -> list[RiskSignal]:
    """
    Return a list of RiskSignal objects for payment/financial risk patterns.

    The sum of score_contributions is capped at 25 by the threat engine.
    """
    text_lower = text.lower()
    signals: list[RiskSignal] = []
    total_claimed = 0

    for pat in _PATTERNS:
        for regex in pat.patterns:
            match = re.search(regex, text_lower)
            if match:
                # Find a verbatim snippet around the match
                start = max(0, match.start() - 40)
                end   = min(len(text), match.end() + 60)
                snippet = text[start:end].strip().replace("\n", " ")

                # Only add each pattern once, cap total
                contrib = min(pat.points, 25 - total_claimed)
                if contrib <= 0:
                    contrib = 0

                signals.append(RiskSignal(
                    category=RiskCategory.FINANCIAL,
                    severity=pat.severity,
                    score_contribution=contrib,
                    evidence=f'"{snippet}"',
                    explanation=pat.explanation,
                ))
                total_claimed += pat.points
                break  # Only trigger each pattern once

    return signals
