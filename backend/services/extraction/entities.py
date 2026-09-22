"""
Named entity extractor — pulls organisation / company names from offer-letter text.

Uses simple pattern-based heuristics (no heavy NER model needed):
  • "Dear <Name>, on behalf of <Company>"
  • "Welcome to <Company>"
  • "from <Company> HR"
  • "Company: <Name>"
  • "Employer: <Name>"
  • Capitalised multi-word sequences near scam keywords
"""
from __future__ import annotations

import re

# Patterns that commonly precede a company name in offer letters
_ORG_PATTERNS = [
    r"(?:on behalf of|behalf of)\s+([A-Z][A-Za-z0-9&\.\-,\s]{2,40}?)(?:\.|,|\n|Ltd|LLC|Inc|Corp|Group|Co\.)",
    r"(?:welcome to|joining)\s+([A-Z][A-Za-z0-9&\.\-,\s]{2,40}?)(?:\.|,|\n)",
    r"(?:from|at)\s+([A-Z][A-Za-z0-9&\.\-,\s]{2,30}?)\s+(?:HR|Recruiter|Team|Department|Office)",
    r"(?:Company|Organization|Employer|Recruiter):\s*([A-Za-z0-9&\.\-,\s]{2,50}?)(?:\n|,|\.)",
    r"([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){0,4})\s+(?:Ltd\.?|LLC\.?|Inc\.?|Corp\.?|Limited|Group|Services|Solutions|Technologies|Consulting)",
]

_CLEAN_RE = re.compile(r"[,\.\s]+$")


def extract_org_names(text: str) -> list[str]:
    """
    Return a list of candidate organisation names mentioned in text.
    """
    found: list[str] = []
    for pattern in _ORG_PATTERNS:
        for match in re.finditer(pattern, text):
            name = _CLEAN_RE.sub("", match.group(1).strip())
            if name and len(name) > 3 and name not in found:
                found.append(name)
    return found[:10]  # cap at 10 results
