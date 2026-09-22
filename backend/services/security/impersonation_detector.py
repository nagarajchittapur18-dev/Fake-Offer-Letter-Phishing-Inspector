"""
Organisation impersonation detector.

Checks whether the organisation names mentioned in the document
match the sender's email domain.

Max contribution: 15 points.
"""
from __future__ import annotations

import re

from schemas import RiskCategory, RiskSignal, Severity
from services.extraction.entities import extract_org_names


# Known legitimate free-email domains — these have no org match by design
_FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "icloud.com", "mail.com",
    "yandex.com", "zoho.com", "gmx.com", "live.com", "msn.com",
}


def _domain_slug(text: str) -> str:
    """Lower-case, strip common TLDs and non-alpha chars for comparison."""
    text = text.lower()
    text = re.sub(r"\.(com|org|net|io|co|uk|gov|edu|in|us|au|ca|de|fr)$", "", text)
    text = re.sub(r"[^a-z0-9]", "", text)
    return text


def _org_slug(name: str) -> str:
    """Normalise org name for comparison."""
    name = name.lower()
    # Remove common suffixes
    name = re.sub(r"\b(ltd|llc|inc|corp|limited|group|services|solutions|technologies|consulting|co)\b", "", name)
    name = re.sub(r"[^a-z0-9]", "", name)
    return name.strip()


def detect_impersonation(text: str, sender_domain: str | None) -> list[RiskSignal]:
    """
    Compare org names mentioned in text against sender_domain.

    Returns RiskSignals if a mismatch is detected.
    """
    signals: list[RiskSignal] = []

    if not sender_domain:
        return signals

    sender_domain = sender_domain.lower().rstrip(".,!?;:")
    domain_slug   = _domain_slug(sender_domain)

    # Free email providers: flag with Email Provider signal, not here
    if sender_domain in _FREE_EMAIL_DOMAINS:
        return signals

    org_names = extract_org_names(text)
    if not org_names:
        return signals

    mismatched: list[str] = []
    for org in org_names:
        org_s = _org_slug(org)
        if org_s and domain_slug and org_s not in domain_slug and domain_slug not in org_s:
            mismatched.append(org)

    if mismatched:
        worst = mismatched[0]
        signals.append(RiskSignal(
            category=RiskCategory.ORG_MISMATCH,
            severity=Severity.HIGH,
            score_contribution=12,
            evidence=f'Organisation "{worst}" mentioned but sender domain is @{sender_domain}',
            explanation=(
                "The company name in the document does not match the sender's email domain. "
                "This is a primary indicator of corporate impersonation."
            ),
        ))

    return signals
