"""
URL extractor — finds all HTTP/HTTPS URLs in arbitrary text.
"""
from __future__ import annotations

import re

_URL_RE = re.compile(
    r"https?://"
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"  # hostname
    r"(?::\d+)?"                            # optional port
    r"(?:/[^\s\"'<>)]*)?"                  # optional path
    r"(?:\?[^\s\"'<>)]*)?",               # optional query
    re.IGNORECASE,
)

# Also capture bare URLs that look like domains without scheme
_BARE_DOMAIN_RE = re.compile(
    r"(?<![/@\w])(?:www\.)"
    r"(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}"
    r"(?:/[^\s\"'<>)]*)?",
    re.IGNORECASE,
)


def extract_urls(text: str) -> list[str]:
    """Return a deduplicated list of URLs found in text."""
    urls: list[str] = list(dict.fromkeys(_URL_RE.findall(text)))
    # Add bare www. URLs with scheme prefix
    for bare in _BARE_DOMAIN_RE.findall(text):
        full = "https://" + bare
        if full not in urls:
            urls.append(full)
    return urls
