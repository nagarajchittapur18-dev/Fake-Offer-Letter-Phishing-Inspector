"""
Scan history routes:
  GET  /api/scans           — list recent scans
  GET  /api/scans/{scan_id} — get full scan result
  DELETE /api/scans/{scan_id} — delete a scan
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from services.history.database import delete_scan, get_scan, list_scans

router = APIRouter()


@router.get("/api/scans", tags=["History"])
async def get_scan_history(limit: int = 50) -> list[dict]:
    """Return a list of recent scan summaries (newest first)."""
    return await list_scans(limit=min(limit, 200))


@router.get("/api/scans/{scan_id}", tags=["History"])
async def get_scan_detail(scan_id: str) -> dict:
    """Return the full result of a specific scan."""
    result = await get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return result


@router.delete("/api/scans/{scan_id}", tags=["History"])
async def delete_scan_record(scan_id: str) -> dict:
    """Delete a scan record."""
    deleted = await delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return {"deleted": True, "scan_id": scan_id}
