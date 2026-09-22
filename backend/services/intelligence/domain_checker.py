"""
Domain intelligence service.

Performs WHOIS lookup (with RDAP fallback) to determine:
  - Domain creation date / age in days
  - Registrar
  - Provider type classification (Free Email / Corporate / New / Unknown)
  - Risk score contribution

Max contribution: 15 points.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

import httpx

from schemas import DomainIntelligence
from services.security.email_analyzer import FREE_EMAIL_PROVIDERS, classify_email_domain


_HIGH_RISK_TLDS = {"xyz", "top", "click", "loan", "gdn", "win", "bid", "stream", "download"}


def extract_domain(text: str) -> Optional[str]:
    """Extract the primary root domain from email addresses, URLs, or raw domain strings."""
    if not text:
        return None

    # 1. Email address
    m = re.search(r"[\w.\-+]+@([\w.\-]+)", text)
    if m:
        return m.group(1).lower().rstrip(".,!?;:")

    # 2. URL
    m = re.search(r"https?://(?:www\.)?([\w.\-]+)", text)
    if m:
        return m.group(1).lower().rstrip(".,!?;:")

    # 3. Bare domain string
    m = re.match(r"^([\w.\-]+\.[a-zA-Z]{2,})$", text.strip())
    if m:
        return m.group(1).lower().rstrip(".,!?;:")

    return None


def _whois_age(domain: str) -> Optional[datetime]:
    """Try python-whois for creation date."""
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        if w.creation_date:
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            return cd if isinstance(cd, datetime) else None
    except Exception:
        pass
    return None


def _rdap_age(domain: str) -> tuple[Optional[datetime], Optional[str]]:
    """Try RDAP for creation date and registrar."""
    try:
        resp = httpx.get(f"https://rdap.org/domain/{domain}", timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            created: Optional[datetime] = None
            registrar: Optional[str]   = None

            for ev in data.get("events", []):
                if ev.get("eventAction") == "registration":
                    ds = ev.get("eventDate", "").replace("Z", "+00:00")
                    try:
                        created = datetime.fromisoformat(ds)
                    except ValueError:
                        pass

            for entity in data.get("entities", []):
                for role in entity.get("roles", []):
                    if role == "registrar":
                        vcard = entity.get("vcardArray", [])
                        if vcard and len(vcard) > 1:
                            for item in vcard[1]:
                                if item[0] == "fn":
                                    registrar = item[3]
                        break

            return created, registrar
    except Exception:
        pass
    return None, None


def check_domain(domain: str) -> DomainIntelligence:
    """
    Full domain intelligence lookup.

    Returns a DomainIntelligence object with score_contribution in [0, 15].
    """
    domain = domain.lower().rstrip(".,!?;:")
    notes: list[str] = []
    score = 0
    created: Optional[datetime] = None
    registrar: Optional[str]    = None

    # ── Skip trivial well-known domains ───────────────────────────────────────
    provider_type, _, _ = classify_email_domain(domain)

    # High-risk TLD check
    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _HIGH_RISK_TLDS:
        score += 3
        notes.append(f"High-risk TLD (.{tld}) associated with spam domains.")

    # ── WHOIS ─────────────────────────────────────────────────────────────────
    created = _whois_age(domain)

    # ── RDAP fallback ─────────────────────────────────────────────────────────
    if not created:
        created, registrar = _rdap_age(domain)
        if not created:
            score += 3
            notes.append("Domain registration data is hidden or unavailable.")

    age_days: Optional[int] = None
    created_iso: Optional[str] = None

    if created:
        if isinstance(created, str):
            try:
                created = datetime.fromisoformat(created.replace("Z", "+00:00"))
            except Exception:
                created = None

    if created:
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days     = (datetime.now(timezone.utc) - created).days
        created_iso  = created.isoformat()

        if age_days < 30:
            score += 15
            notes.append(f"Domain registered only {age_days} days ago — extremely high risk.")
        elif age_days < 90:
            score += 10
            notes.append(f"Domain registered {age_days} days ago — recently created domains are often fraudulent.")
        elif age_days < 365:
            score += 5
            notes.append(f"Domain registered {age_days} days ago — less than one year old.")
        else:
            notes.append(f"Domain age: {age_days} days — established domain.")

    return DomainIntelligence(
        domain=domain,
        age_days=age_days,
        created=created_iso,
        provider_type=provider_type,
        registrar=registrar,
        score_contribution=min(score, 15),
        notes=notes,
    )
