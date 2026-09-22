"""
Report routes:
  GET /api/report/{scan_id} — download PDF forensic report
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from services.history.database import get_scan
from services.reports.pdf_report import generate_pdf_report

router = APIRouter()


@router.get("/api/report/{scan_id}", tags=["Report"])
async def download_report(scan_id: str) -> Response:
    """Generate and return a PDF forensic report for the given scan."""
    result = await get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    try:
        pdf_bytes = generate_pdf_report(result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {exc}")

    filename = f"phishing-report-{scan_id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
