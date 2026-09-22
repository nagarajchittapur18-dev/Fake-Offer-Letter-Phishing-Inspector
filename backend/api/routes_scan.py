"""
Scan routes:
  POST /api/scan/text   — scan raw text
  POST /api/scan/file   — scan uploaded file
  POST /api/scan/url    — scan a URL
  POST /api/scan        — unified scan (multipart form with optional file)
"""
from __future__ import annotations

import asyncio
import os
from typing import Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.concurrency import run_in_threadpool

from schemas import (
    InputType,
    ScanResponse,
    ScanTextRequest,
    new_scan_id,
    utcnow_iso,
)
from services.ai.gemini_analyzer import analyze_with_gemini
from services.document.docx_parser import extract_docx
from services.document.email_parser import parse_eml
from services.document.pdf_parser import extract_pdf
from services.extraction.emails import extract_domains_from_emails, primary_sender_domain
from services.extraction.urls import extract_urls
from services.history.database import save_scan
from services.intelligence.domain_checker import check_domain, extract_domain
from services.scoring.threat_engine import compute_threat
from services.security.email_analyzer import detect_email_provider_risk, detect_reply_to_mismatch
from services.security.impersonation_detector import detect_impersonation
from services.security.payment_detector import detect_payment_risk
from services.security.recruitment_detector import detect_recruitment_anomalies
from services.security.urgency_detector import detect_urgency
from services.security.url_analyzer import analyse_urls, url_analyses_to_signals

router = APIRouter()

MAX_FILE_BYTES = int(os.getenv("MAX_FILE_SIZE_MB", "10")) * 1024 * 1024
ACCEPTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".eml"}


# ── Core pipeline ──────────────────────────────────────────────────────────────

async def _run_pipeline(
    text:         str,
    sender_email: Optional[str],
    extra_urls:   list[str],
    input_type:   InputType,
    source_name:  Optional[str],
    metadata:     dict,
) -> ScanResponse:
    """
    Orchestrate all detectors, intelligence lookups, and scoring.
    """
    scan_id    = new_scan_id()
    scanned_at = utcnow_iso()

    # ── 1. Determine sender domain ────────────────────────────────────────────
    sender_domain = primary_sender_domain(sender_email, text)

    # ── 2. Collect all signals in parallel where possible ─────────────────────
    payment_signals    = detect_payment_risk(text)
    urgency_signals    = detect_urgency(text)
    recruit_signals    = detect_recruitment_anomalies(text)
    provider_signals   = detect_email_provider_risk(sender_domain)
    imperson_signals   = detect_impersonation(text, sender_domain)

    # Reply-To mismatch (only available from EML parsing)
    reply_to_signals = []
    if metadata.get("has_reply_to_mismatch"):
        reply_to_signals = detect_reply_to_mismatch(
            metadata.get("from_domain"), metadata.get("reply_to_domain")
        )

    # ── 3. URL analysis ───────────────────────────────────────────────────────
    embedded_urls = extract_urls(text)
    all_urls      = list(dict.fromkeys(extra_urls + embedded_urls + metadata.get("embedded_urls", [])))

    url_analyses = await run_in_threadpool(analyse_urls, all_urls[:5])
    url_signals  = url_analyses_to_signals(url_analyses)

    # ── 4. Domain intelligence ────────────────────────────────────────────────
    domain_to_check = sender_domain or extract_domain(text)
    domain_intel    = await run_in_threadpool(check_domain, domain_to_check) if domain_to_check else None

    # ── 5. Gemini AI analysis ─────────────────────────────────────────────────
    ai_analysis = await run_in_threadpool(analyze_with_gemini, text)

    # ── 6. Merge all signals ──────────────────────────────────────────────────
    all_signals = (
        payment_signals +
        urgency_signals +
        recruit_signals +
        provider_signals +
        imperson_signals +
        reply_to_signals +
        url_signals
    )

    # ── 7. Score ──────────────────────────────────────────────────────────────
    threat_index, risk_level, breakdown, verdict, recs = compute_threat(
        all_signals, domain_intel, ai_analysis
    )

    result = ScanResponse(
        scan_id=scan_id,
        threat_index=threat_index,
        risk_level=risk_level,
        verdict_summary=verdict,
        risk_signals=all_signals,
        score_breakdown=breakdown,
        domain_intelligence=domain_intel,
        url_analyses=url_analyses,
        ai_analysis=ai_analysis,
        recommendations=recs,
        metadata={
            **{k: v for k, v in metadata.items() if isinstance(v, (str, int, float, bool, type(None)))},
            "source_name": source_name,
            "sender_domain": sender_domain,
        },
        input_type=input_type,
        scanned_at=scanned_at,
    )

    # ── 8. Persist to history ─────────────────────────────────────────────────
    try:
        await save_scan(
            scan_id=scan_id,
            created_at=scanned_at,
            input_type=input_type.value,
            source_name=source_name,
            domain=domain_to_check,
            threat_index=threat_index,
            risk_level=risk_level.value,
            signals=[s.model_dump() for s in all_signals],
            full_result=result.model_dump(mode="json"),
        )
    except Exception:
        pass  # History failure must never break scan response

    return result


# ── Route: POST /api/scan/text ─────────────────────────────────────────────────

@router.post("/api/scan/text", response_model=ScanResponse, tags=["Scan"])
async def scan_text(req: ScanTextRequest) -> ScanResponse:
    return await _run_pipeline(
        text=req.text,
        sender_email=req.sender_email,
        extra_urls=[req.url] if req.url else [],
        input_type=InputType.TEXT,
        source_name=None,
        metadata={},
    )


# ── Route: POST /api/scan/url ──────────────────────────────────────────────────

@router.post("/api/scan/url", response_model=ScanResponse, tags=["Scan"])
async def scan_url(url: str = Form(...)) -> ScanResponse:
    """Fetch the content of a URL and run the full pipeline on it."""
    import httpx  # type: ignore
    from services.security.url_analyzer import _is_ssrf_target
    from urllib.parse import urlparse

    parsed   = urlparse(url)
    hostname = parsed.hostname or ""
    if _is_ssrf_target(hostname):
        raise HTTPException(status_code=400, detail="SSRF-blocked URL.")

    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, max_redirects=5) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            text = resp.text[:50_000]
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not fetch URL: {exc}")

    return await _run_pipeline(
        text=text,
        sender_email=None,
        extra_urls=[url],
        input_type=InputType.URL,
        source_name=url[:200],
        metadata={},
    )


# ── Route: POST /api/scan/file ─────────────────────────────────────────────────

@router.post("/api/scan/file", response_model=ScanResponse, tags=["Scan"])
async def scan_file(file: UploadFile = File(...)) -> ScanResponse:
    content = await file.read()
    if len(content) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(content)/1_048_576:.1f} MB). Max 10 MB.",
        )

    filename  = (file.filename or "").lower()
    ext       = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    if ext not in ACCEPTED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported format '{ext}'. Accepted: PDF, DOCX, TXT, EML.",
        )

    text: str         = ""
    metadata: dict    = {}
    sender_email: str = ""

    if ext == ".pdf":
        text, metadata = await run_in_threadpool(extract_pdf, content)
    elif ext == ".docx":
        text, metadata = await run_in_threadpool(extract_docx, content)
    elif ext == ".eml":
        text, metadata = await run_in_threadpool(parse_eml, content)
        sender_email   = metadata.get("from", "")
    else:
        text = content.decode("utf-8", errors="replace")

    return await _run_pipeline(
        text=text,
        sender_email=sender_email or None,
        extra_urls=[],
        input_type=InputType.FILE,
        source_name=file.filename,
        metadata=metadata,
    )


# ── Route: POST /api/scan — unified multipart form ─────────────────────────────

@router.post("/api/scan", response_model=ScanResponse, tags=["Scan"])
async def scan(
    text:         Optional[str]        = Form(None),
    sender_email: Optional[str]        = Form(None),
    url:          Optional[str]        = Form(None),
    file:         Optional[UploadFile] = File(None),
) -> ScanResponse:
    if file and file.filename:
        return await scan_file(file)

    if url and not text:
        return await scan_url(url)

    if not text:
        raise HTTPException(status_code=422, detail="Provide text, a file, or a URL.")

    return await _run_pipeline(
        text=text,
        sender_email=sender_email,
        extra_urls=[url] if url else [],
        input_type=InputType.TEXT,
        source_name=None,
        metadata={},
    )
