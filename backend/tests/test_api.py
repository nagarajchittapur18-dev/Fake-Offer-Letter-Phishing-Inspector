"""
FastAPI integration tests for scan API endpoints.
Uses TestClient (synchronous) so no async setup needed.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_root_returns_200():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "name" in data
    assert "endpoints" in data


def test_health_returns_components():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert "status" in data
    assert "components" in data
    assert "gemini_ai" in data["components"]
    assert "domain_lookup" in data["components"]
    assert "ocr" in data["components"]


def test_scan_text_payment_scam():
    resp = client.post("/api/scan/text", json={
        "text": (
            "Congratulations! You are hired without an interview. "
            "Please send a wire transfer to purchase equipment. "
            "Contact HR on Telegram immediately."
        )
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["threat_index"] > 25
    assert data["risk_level"] in ("SUSPICIOUS", "HIGH", "CRITICAL")
    assert len(data["risk_signals"]) > 0
    assert "score_breakdown" in data
    assert "recommendations" in data


def test_scan_text_clean():
    resp = client.post("/api/scan/text", json={
        "text": (
            "We are pleased to offer you the position of Software Engineer "
            "at an annual salary of $80,000. Please review the attached contract "
            "and sign by next Friday."
        )
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_level"] in ("LOW", "SUSPICIOUS")


def test_scan_text_returns_scan_id():
    resp = client.post("/api/scan/text", json={"text": "Test document for scanning purposes."})
    assert resp.status_code == 200
    data = resp.json()
    assert "scan_id" in data
    assert len(data["scan_id"]) > 10


def test_scan_text_too_short():
    resp = client.post("/api/scan/text", json={"text": "hi"})
    assert resp.status_code == 422


def test_scan_unified_with_text():
    resp = client.post("/api/scan", data={
        "text": "This is a test phishing document with immediate hire without interview."
    })
    assert resp.status_code == 200


def test_scan_history_returns_list():
    # Perform a scan first
    client.post("/api/scan/text", json={"text": "Test scan for history check. No issues here."})
    resp = client.get("/api/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_scan_history_get_existing():
    # Perform a scan and retrieve it
    scan_resp = client.post("/api/scan/text", json={"text": "Test scan for history retrieval check."})
    scan_id = scan_resp.json()["scan_id"]
    resp = client.get(f"/api/scans/{scan_id}")
    assert resp.status_code == 200
    assert resp.json()["scan_id"] == scan_id


def test_scan_history_404_on_missing():
    resp = client.get("/api/scans/nonexistent-id-12345")
    assert resp.status_code == 404


def test_report_download_pdf():
    scan_resp = client.post("/api/scan/text", json={"text": "Test for PDF report generation. Wire transfer scam."})
    scan_id   = scan_resp.json()["scan_id"]
    resp      = client.get(f"/api/report/{scan_id}")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert len(resp.content) > 1000  # non-trivial PDF


def test_report_404_on_missing():
    resp = client.get("/api/report/nonexistent-report-999")
    assert resp.status_code == 404


def test_delete_scan():
    scan_resp = client.post("/api/scan/text", json={"text": "Test for deletion. Equipment scam check."})
    scan_id   = scan_resp.json()["scan_id"]
    del_resp  = client.delete(f"/api/scans/{scan_id}")
    assert del_resp.status_code == 200
    # Verify gone
    get_resp = client.get(f"/api/scans/{scan_id}")
    assert get_resp.status_code == 404
