"""
URL risk analyser with SSRF protection.

Checks each URL for:
  • SSRF-blocked addresses (private ranges, loopback, metadata services)
  • URL shorteners (bit.ly, tinyurl, etc.)
  • HTTP (non-HTTPS)
  • Suspiciously long or obfuscated paths
  • Redirect chains
  • Reachability (optional HEAD request, timeout-protected)

Max contribution per URL: 10 points (aggregate).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

import httpx

from schemas import RiskCategory, RiskSignal, Severity, URLAnalysis

# ── SSRF-blocked private IP ranges ────────────────────────────────────────────
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_INTERNAL_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata.aws"}

# Known URL shorteners
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "rebrand.ly", "linktr.ee",
    "shorte.st", "clk.sh", "lnkd.in", "rb.gy", "cutt.ly", "v.gd",
}


def _is_ssrf_target(hostname: str) -> bool:
    """Return True if hostname resolves to a private/loopback address."""
    if hostname.lower() in _INTERNAL_HOSTNAMES:
        return True
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _, _, _, _, sockaddr in addrs:
            ip_str = sockaddr[0]
            try:
                ip = ipaddress.ip_address(ip_str)
                for net in _PRIVATE_NETWORKS:
                    if ip in net:
                        return True
            except ValueError:
                pass
    except Exception:
        pass
    return False


def _score_url_suspicion(parsed: "ParseResult", is_shortener: bool, is_http: bool, path_len: int) -> int:  # type: ignore
    score = 0
    if is_shortener:
        score += 4
    if is_http:
        score += 3
    if path_len > 200:
        score += 2
    if re.search(r"(?:%[0-9a-f]{2}){3,}", parsed.path, re.IGNORECASE):
        score += 3  # Heavy URL encoding
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", parsed.netloc):
        score += 4  # Raw IP address
    return score


def analyse_url(url: str, timeout: float = 6.0) -> URLAnalysis:
    """
    Analyse a single URL.  Safe to call; exceptions handled internally.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return URLAnalysis(
            url=url, is_reachable=False, is_suspicious=True,
            is_ssrf_blocked=False, score_contribution=2,
            evidence=f"Malformed URL: {url[:100]}",
        )

    hostname = parsed.hostname or ""
    is_http  = parsed.scheme == "http"
    is_shortener = hostname.lower() in _SHORTENERS
    path_len = len(parsed.path)

    # ── SSRF guard ────────────────────────────────────────────────────────────
    if _is_ssrf_target(hostname):
        return URLAnalysis(
            url=url, is_reachable=False, is_suspicious=True,
            is_ssrf_blocked=True, score_contribution=0,
            evidence=f"Blocked (SSRF protection): {hostname}",
        )

    susp_score = _score_url_suspicion(parsed, is_shortener, is_http, path_len)

    # ── Optional reachability check ────────────────────────────────────────────
    is_reachable   = False
    final_url      = None
    status_code    = None
    redirect_count = 0

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, max_redirects=5) as client:
            resp = client.head(url, headers={"User-Agent": "Mozilla/5.0"})
            is_reachable   = True
            status_code    = resp.status_code
            final_url      = str(resp.url)
            redirect_count = len(resp.history)

            if redirect_count > 2:
                susp_score += 2
            if final_url != url and urlparse(final_url).hostname != hostname:
                susp_score += 3  # Cross-domain redirect
    except Exception:
        susp_score += 1  # Unreachable = slight suspicion

    is_suspicious = susp_score >= 3
    contrib       = min(susp_score, 10)

    evidence_parts = []
    if is_shortener:
        evidence_parts.append(f"URL shortener ({hostname})")
    if is_http:
        evidence_parts.append("non-HTTPS")
    if redirect_count > 2:
        evidence_parts.append(f"{redirect_count} redirects")
    if not is_reachable:
        evidence_parts.append("unreachable")
    evidence = "; ".join(evidence_parts) if evidence_parts else f"URL: {url[:100]}"

    return URLAnalysis(
        url=url,
        is_reachable=is_reachable,
        is_suspicious=is_suspicious,
        is_ssrf_blocked=False,
        final_url=final_url,
        status_code=status_code,
        redirect_count=redirect_count,
        score_contribution=contrib,
        evidence=evidence,
    )


def analyse_urls(urls: list[str], max_urls: int = 5, timeout: float = 6.0) -> list[URLAnalysis]:
    """Analyse up to max_urls URLs."""
    return [analyse_url(u, timeout=timeout) for u in urls[:max_urls]]


def url_analyses_to_signals(url_analyses: list[URLAnalysis]) -> list[RiskSignal]:
    """Convert URLAnalysis objects to RiskSignals for suspicious URLs."""
    signals: list[RiskSignal] = []
    total = 0
    for ua in url_analyses:
        if ua.is_suspicious and not ua.is_ssrf_blocked:
            contrib = min(ua.score_contribution, 10 - total)
            if contrib <= 0:
                break
            signals.append(RiskSignal(
                category=RiskCategory.URL,
                severity=Severity.HIGH if ua.score_contribution >= 6 else Severity.MEDIUM,
                score_contribution=contrib,
                evidence=ua.evidence,
                explanation=(
                    "This URL shows characteristics common in phishing campaigns: "
                    "URL shorteners hide the true destination; "
                    "HTTP links are unencrypted; "
                    "cross-domain redirects may lead to credential-harvesting sites."
                ),
            ))
            total += ua.score_contribution
    return signals
