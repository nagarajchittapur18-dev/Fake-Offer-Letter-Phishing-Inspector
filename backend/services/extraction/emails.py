"""
Email address extractor.
"""
from __future__ import annotations

import re

_EMAIL_RE = re.compile(r"[\w\.\+\-]+@[\w\.\-]+\.[a-zA-Z]{2,}", re.IGNORECASE)


def extract_emails(text: str) -> list[str]:
    """Return a deduplicated list of email addresses found in text."""
    return list(dict.fromkeys(m.lower() for m in _EMAIL_RE.findall(text)))


def extract_domains_from_emails(text: str) -> list[str]:
    """Return domains of all email addresses found in text."""
    domains = []
    for addr in extract_emails(text):
        parts = addr.split("@", 1)
        if len(parts) == 2:
            domain = parts[1].rstrip(".,!?;:")
            if domain not in domains:
                domains.append(domain)
    return domains


def primary_sender_domain(sender_email: str | None, text: str) -> str | None:
    """
    Determine the primary sender domain.

    Priority: explicit sender_email → first email found in text.
    """
    if sender_email:
        match = re.search(r"@([\w\.\-]+)", sender_email)
        if match:
            return match.group(1).lower().rstrip(".,!?;:")

    emails = extract_emails(text)
    if emails:
        match = re.search(r"@([\w\.\-]+)", emails[0])
        if match:
            return match.group(1).lower().rstrip(".,!?;:")

    return None
