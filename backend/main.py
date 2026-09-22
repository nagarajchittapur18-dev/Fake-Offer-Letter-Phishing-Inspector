"""
Fake Offer Letter & Phishing Inspector — V2
FastAPI application entry point.
"""
from __future__ import annotations

import os
import sys

# Allow running directly from the backend directory
sys.path.insert(0, os.path.dirname(__file__))

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes_health  import router as health_router
from api.routes_history import router as history_router
from api.routes_report  import router as report_router
from api.routes_scan    import router as scan_router
from services.history.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise the database on startup."""
    await init_db()
    yield


app = FastAPI(
    title="Fake Offer Letter & Phishing Inspector",
    description=(
        "Production-quality API for detecting employment scams, phishing, "
        "advance-fee fraud, and counterfeit offer letters. V2."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
_origins_raw = os.getenv("CORS_ORIGINS", "*")
_origins = ["*"] if _origins_raw == "*" else [o.strip() for o in _origins_raw.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(health_router)
app.include_router(scan_router)
app.include_router(history_router)
app.include_router(report_router)


@app.get("/", tags=["Meta"])
async def root() -> dict:
    return {
        "name":    "Fake Offer Letter & Phishing Inspector",
        "version": "2.0.0",
        "endpoints": {
            "health":         "GET  /api/health",
            "scan_text":      "POST /api/scan/text",
            "scan_file":      "POST /api/scan/file",
            "scan_url":       "POST /api/scan/url",
            "scan_unified":   "POST /api/scan",
            "history_list":   "GET  /api/scans",
            "history_get":    "GET  /api/scans/{scan_id}",
            "history_delete": "DELETE /api/scans/{scan_id}",
            "report":         "GET  /api/report/{scan_id}",
            "docs":           "GET  /docs",
        },
    }
