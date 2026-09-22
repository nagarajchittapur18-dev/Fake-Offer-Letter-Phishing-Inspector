"""
GET /api/health — live component status check.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter

from schemas import ComponentStatus, HealthResponse

router = APIRouter()


def _check_gemini() -> ComponentStatus:
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return ComponentStatus(status="offline", message="GEMINI_API_KEY not set")
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    return ComponentStatus(status="online", message=f"Configured: {model}")


def _check_domain_lookup() -> ComponentStatus:
    try:
        import whois  # noqa: F401
        import httpx  # noqa: F401
        return ComponentStatus(status="online", message="WHOIS + RDAP available")
    except ImportError as e:
        return ComponentStatus(status="degraded", message=str(e))


def _check_ocr() -> ComponentStatus:
    try:
        from services.document.ocr import is_ocr_available
        if is_ocr_available():
            return ComponentStatus(status="online", message="Tesseract OCR ready")
        return ComponentStatus(status="offline", message="Tesseract binary not installed")
    except Exception as e:
        return ComponentStatus(status="offline", message=str(e))


def _check_database() -> ComponentStatus:
    try:
        import aiosqlite  # noqa: F401
        return ComponentStatus(status="online", message="aiosqlite ready")
    except ImportError as e:
        return ComponentStatus(status="offline", message=str(e))


def _check_pdf() -> ComponentStatus:
    try:
        import pypdf  # noqa: F401
        return ComponentStatus(status="online", message=f"pypdf {pypdf.__version__}")
    except Exception as e:
        return ComponentStatus(status="offline", message=str(e))


@router.get("/api/health", response_model=HealthResponse, tags=["Health"])
async def health_check() -> HealthResponse:
    gemini  = _check_gemini()
    domain  = _check_domain_lookup()
    ocr     = _check_ocr()
    db      = _check_database()
    pdf     = _check_pdf()

    statuses = [gemini.status, domain.status, ocr.status, db.status, pdf.status]
    if all(s == "online" for s in statuses):
        overall = "healthy"
    elif all(s == "offline" for s in statuses):
        overall = "unhealthy"
    else:
        overall = "degraded"

    return HealthResponse(
        status=overall,
        version="2.0.0",
        components={
            "gemini_ai":      gemini,
            "domain_lookup":  domain,
            "ocr":            ocr,
            "database":       db,
            "pdf_parser":     pdf,
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
