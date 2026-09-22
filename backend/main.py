import os
import sys
from fastapi import FastAPI, HTTPException, File, Form, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from typing import Optional

# ── Ensure the backend root is on sys.path so relative imports work cleanly ───
sys.path.insert(0, os.path.dirname(__file__))

load_dotenv()

from schemas import ScanResponse, DomainDetails
from services.domain_checker import extract_domain, check_domain
from services.heuristics import analyze_text
from services.gemini_analyzer import analyze_with_gemini
from services.aggregator import compute_threat_index, merge_flags, build_recommendations
from services.file_extractor import extract_text_from_file

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Fake Offer Letter & Phishing Inspector API",
    description="Deep-semantic + heuristic scam detection powered by Gemini 2.5 Flash.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # tighten to frontend origin in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Health ────────────────────────────────────────────────────────────────────
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "message": "Fake Offer Letter & Phishing Inspector API v2 is running.",
    }


# ── Flat shape helper ─────────────────────────────────────────────────────────
def _flat_response(r: ScanResponse) -> dict:
    """
    Returns a flat JSON shape consumed directly by index.html:
    {
      threat_index, verdict_summary, safety_recommendations, score_breakdown,
      domain_info: { domain, days_old, creation_date, score_penalty },
      ai_analysis: { ...booleans, ai_confidence_score },
      flags: [ { category, severity, evidence } ]
    }
    """
    dom = r.domain_details
    return {
        "threat_index":           r.threat_index,
        "verdict_summary":        r.verdict_summary,
        "safety_recommendations": r.safety_recommendations,
        "score_breakdown":        r.score_breakdown,
        "domain_info": {
            "domain":        dom.domain        if dom else None,
            "days_old":      dom.age_in_days   if dom else None,
            "creation_date": dom.creation_date if dom else None,
            "score_penalty": dom.penalty       if dom else 0,
        },
        "ai_analysis": {
            "payment_demand_detected":   r.ai_analysis.payment_demand_detected,
            "urgency_detected":          r.ai_analysis.urgency_detected,
            "interview_bypass_detected": r.ai_analysis.interview_bypass_detected,
            "free_email_domain_used":    r.ai_analysis.free_email_domain_used,
            "ai_confidence_score":       r.ai_analysis.ai_confidence_score,
            "ai_audit_available":        r.ai_analysis.ai_audit_available,
        },
        "flags": [
            {"category": f.category, "severity": f.severity, "evidence": f.evidence}
            for f in r.flags
        ],
    }


# ── Scan ──────────────────────────────────────────────────────────────────────
@app.post("/api/scan", response_model=ScanResponse)
async def scan(
    file: Optional[UploadFile] = File(None),
    text: Optional[str]        = Form(""),
    url:  Optional[str]        = Form(""),
):
    """
    Multipart-form endpoint.  Accepts an uploaded document (PDF/DOCX/TXT/EML)
    and/or raw pasted text plus an optional URL/email for domain intelligence.

    Pipeline
    --------
    1. File extraction  → primary offer payload text.
    2. Domain extraction & WHOIS → domain_penalty.
    3. Regex heuristics           → heuristics_penalty.
    4. Gemini 2.5 Flash           → ai_confidence_score + flags.
    5. Aggregation formula        → Threat Index 0–100.
    6. Recommendations            → actionable safety steps.
    """
    # ── Gather payload text ───────────────────────────────────────────────────
    file_text = ""
    file_name = None

    if file and file.filename:
        file_text = await extract_text_from_file(file)
        file_name = file.filename

    raw_text = (text or "").strip()

    # Prioritise file content; fall back to pasted text; concatenate if both.
    if file_text and raw_text:
        combined_text = f"{file_text}\n\n---\nAdditional context:\n{raw_text}"
    elif file_text:
        combined_text = file_text
    elif raw_text:
        combined_text = raw_text
    else:
        raise HTTPException(
            status_code=400,
            detail="Please upload a document or paste offer text before scanning.",
        )

    url_clean = (url or "").strip()
    if url_clean:
        combined_text = f"URL/Email: {url_clean}\n\n{combined_text}"

    # ── Step 1: Domain extraction ─────────────────────────────────────────────
    domain_source = url_clean or combined_text
    domain = extract_domain(domain_source)

    # ── Step 2: Domain validation ─────────────────────────────────────────────
    domain_info = check_domain(domain) if domain else {
        "domain": None, "creation_date": None, "age_in_days": None, "penalty": 0
    }
    domain_penalty = domain_info["penalty"]
    domain_details = DomainDetails(**domain_info)

    # ── Step 3: Heuristic scan ────────────────────────────────────────────────
    heuristics   = analyze_text(combined_text, domain)
    heur_penalty = heuristics["heuristics_penalty"]
    heur_findings= heuristics["findings"]

    # ── Step 4: Gemini AI analysis ────────────────────────────────────────────
    ai_analysis = analyze_with_gemini(combined_text)

    # ── Step 5: Threat Index ──────────────────────────────────────────────────
    threat_index, breakdown = compute_threat_index(
        ai=ai_analysis,
        heuristics_penalty=heur_penalty,
        domain_penalty=domain_penalty,
    )

    # ── Step 6: Flags + Recommendations ──────────────────────────────────────
    merged_flags    = merge_flags(ai_analysis.flags, heur_findings)
    recommendations = build_recommendations(
        ai=ai_analysis,
        heuristics_penalty=heur_penalty,
        domain_penalty=domain_penalty,
        domain_age_days=domain_info.get("age_in_days"),
    )

    response = ScanResponse(
        threat_index=threat_index,
        verdict_summary=ai_analysis.verdict_summary,
        flags=merged_flags,
        domain_details=domain_details,
        ai_analysis=ai_analysis,
        safety_recommendations=recommendations,
        score_breakdown=breakdown,
    )
    return response


# ── Flat alias ─────────────────────────────────────────────────────────────────
# Consumed by index.html directly via fetch('/api/scan/flat', FormData)
@app.post("/api/scan/flat")
async def scan_flat(
    file: Optional[UploadFile] = File(None),
    text: Optional[str]        = Form(""),
    url:  Optional[str]        = Form(""),
):
    """Same pipeline as /api/scan, returns the simplified flat JSON the HTML UI expects."""
    from fastapi import Request
    r = await scan(file=file, text=text, url=url)
    return _flat_response(r)
