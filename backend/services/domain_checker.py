import re
import whois
import httpx
from datetime import datetime, timezone

def extract_domain(text: str) -> str | None:
    """Extract root domain from URLs or raw emails."""
    if not text:
        return None
        
    extracted = None
    
    # Match emails
    email_match = re.search(r'[\w\.-]+@([\w\.-]+)', text)
    if email_match:
        extracted = email_match.group(1).lower()
    else:
        # Match URLs
        url_match = re.search(r'https?://(?:www\.)?([\w\.-]+)', text)
        if url_match:
            extracted = url_match.group(1).lower()
        else:
            # Fallback to direct domain string
            domain_match = re.search(r'^([\w\.-]+\.[a-zA-Z]{2,})$', text.strip())
            if domain_match:
                extracted = domain_match.group(1).lower()

    if extracted:
        return extracted.rstrip('.,!?;:')
        
    return None

def check_domain(domain: str) -> dict:
    """
    Query whois (or RDAP fallback) for registration age.
    Calculates a risk penalty based on domain age and lookup success.
    """
    if not domain:
        return {"domain": None, "creation_date": None, "age_in_days": None, "penalty": 0}

    creation_date = None
    penalty = 0

    # High-risk TLD check (newly registered generic TLDs)
    tld = domain.split('.')[-1]
    if tld in ['xyz', 'top']:
        penalty += 10

    # Try whois
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
    except Exception:
        pass

    # Fallback to RDAP if whois fails
    if not creation_date:
        try:
            # Using rdap.org to redirect to the authoritative RDAP server
            response = httpx.get(f"https://rdap.org/domain/{domain}", timeout=5.0)
            if response.status_code == 200:
                data = response.json()
                for event in data.get('events', []):
                    if event.get('eventAction') == 'registration':
                        # Parse ISO8601 date, replacing Z with +00:00 for python 3.10- compatibility
                        date_str = event.get('eventDate').replace('Z', '+00:00')
                        creation_date = datetime.fromisoformat(date_str)
                        break
        except Exception:
            pass

    age_in_days = None

    if creation_date:
        # Convert string to datetime if needed
        if isinstance(creation_date, str):
            try:
                creation_date = datetime.fromisoformat(creation_date)
            except ValueError:
                # If parsing fails, treat as missing date
                creation_date = None

    if creation_date:
        # Ensure timezone awareness for comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
            
        now = datetime.now(timezone.utc)
        age = (now - creation_date).days
        age_in_days = age

        if age < 30:
            penalty += 30
        elif 30 <= age <= 90:
            penalty += 15
        else:
            penalty += 0
    else:
        # Failed/hidden lookup penalty
        penalty += 10

    return {
        "domain": domain,
        "creation_date": creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date) if creation_date else None,
        "age_in_days": age_in_days,
        "penalty": penalty
    }
