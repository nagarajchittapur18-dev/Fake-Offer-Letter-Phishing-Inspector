"""
Email sender analysis.

Classifies the sender's email domain as:
  - Free Email Provider  (→ 10 points)
  - Corporate            (→ 0 points)
  - Unknown              (→ 3 points)

Also handles Reply-To domain mismatch detection for EML inputs.
"""
from __future__ import annotations

from schemas import RiskCategory, RiskSignal, Severity


FREE_EMAIL_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "yahoo.co.in",
    "hotmail.com", "hotmail.co.uk", "outlook.com", "live.com",
    "msn.com", "aol.com", "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "tutanota.com", "tutanota.de",
    "mail.com", "gmx.com", "gmx.net", "yandex.com", "yandex.ru",
    "zoho.com", "zohomail.com", "mailinator.com", "guerrillamail.com",
    "tempmail.com", "10minutemail.com", "throwaway.email",
    "dispostable.com", "sharklasers.com", "guerrillamailblock.com",
}


def classify_email_domain(domain: str | None) -> tuple[str, int, str]:
    """
    Return (provider_type_label, score_contribution, explanation).
    """
    if not domain:
        return "Unknown", 0, "No sender domain was identified."

    domain_lower = domain.lower().rstrip(".,!?;:")

    if domain_lower in FREE_EMAIL_PROVIDERS:
        return (
            "Free Email Provider",
            10,
            f"The sender uses a free consumer email service ({domain_lower}). "
            "Legitimate organisations use their own corporate domain.",
        )

    # Very short domain could be suspicious
    parts = domain_lower.split(".")
    if len(parts) < 2:
        return "Unknown", 3, f"The sender domain '{domain}' appears malformed."

    return "Corporate Domain", 0, f"Sender domain @{domain_lower} appears to be a custom domain."


def detect_email_provider_risk(sender_domain: str | None) -> list[RiskSignal]:
    """
    Return a RiskSignal if the sender domain is a free email provider.
    Max contribution: 10 points.
    """
    signals: list[RiskSignal] = []
    if not sender_domain:
        return signals

    provider_type, score, explanation = classify_email_domain(sender_domain)

    if score > 0:
        signals.append(RiskSignal(
            category=RiskCategory.EMAIL,
            severity=Severity.HIGH if score >= 10 else Severity.MEDIUM,
            score_contribution=min(score, 10),
            evidence=f"Sender domain: @{sender_domain}",
            explanation=explanation,
        ))

    return signals


def detect_reply_to_mismatch(from_domain: str | None, reply_to_domain: str | None) -> list[RiskSignal]:
    """
    Return a RiskSignal if Reply-To domain differs from From domain.
    Contributes to ORG_MISMATCH category (up to 15 pts total with impersonation).
    """
    signals: list[RiskSignal] = []
    if not from_domain or not reply_to_domain:
        return signals

    if from_domain.lower() != reply_to_domain.lower():
        signals.append(RiskSignal(
            category=RiskCategory.ORG_MISMATCH,
            severity=Severity.HIGH,
            score_contribution=8,
            evidence=f"From domain @{from_domain} vs Reply-To domain @{reply_to_domain}",
            explanation=(
                "The Reply-To address uses a different domain than the From address. "
                "This is a phishing technique to intercept replies."
            ),
        ))

    return signals
