"""
Core pipeline unit tests.
Tests domain extraction, email parsing, URL extraction, and entity extraction.
"""
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from services.intelligence.domain_checker import extract_domain
from services.extraction.urls import extract_urls
from services.extraction.emails import extract_emails, primary_sender_domain
from services.extraction.entities import extract_org_names


# ── Domain extraction ──────────────────────────────────────────────────────────

def test_extract_domain_from_email():
    text = "Contact us at hr@microsoft.com for more info."
    assert extract_domain(text) == "microsoft.com"

def test_extract_domain_from_url():
    text = "Visit https://www.amazon-jobs.xyz/apply for details."
    assert extract_domain(text) == "amazon-jobs.xyz"

def test_extract_domain_bare():
    assert extract_domain("example.com") == "example.com"

def test_extract_domain_strips_trailing_punctuation():
    text = "Contact recruiter@fakecompany.com."
    domain = extract_domain(text)
    assert domain and not domain.endswith(".")

def test_extract_domain_returns_none_for_empty():
    assert extract_domain("") is None
    assert extract_domain(None) is None  # type: ignore


# ── URL extraction ─────────────────────────────────────────────────────────────

def test_extract_urls_finds_https():
    text = "Apply at https://careers.example.com/apply?ref=email today!"
    urls = extract_urls(text)
    assert any("careers.example.com" in u for u in urls)

def test_extract_urls_finds_http():
    text = "Visit http://bit.ly/abc123 to confirm."
    urls = extract_urls(text)
    assert any("bit.ly" in u for u in urls)

def test_extract_urls_deduplicates():
    text = "Go to https://example.com and https://example.com for more."
    urls = extract_urls(text)
    assert urls.count("https://example.com") == 1

def test_extract_urls_empty_text():
    assert extract_urls("") == []

def test_extract_urls_no_urls():
    assert extract_urls("This is plain text with no links.") == []


# ── Email extraction ───────────────────────────────────────────────────────────

def test_extract_emails_finds_basic():
    text = "Contact hr@company.com or support@fake.io for details."
    emails = extract_emails(text)
    assert "hr@company.com" in emails
    assert "support@fake.io" in emails

def test_extract_emails_lowercase():
    emails = extract_emails("Email HR@COMPANY.COM now.")
    assert "hr@company.com" in emails

def test_primary_sender_from_explicit():
    domain = primary_sender_domain("hr@microsoft.com", "some text")
    assert domain == "microsoft.com"

def test_primary_sender_falls_back_to_text():
    domain = primary_sender_domain(None, "Sent from recruiter@gmail.com")
    assert domain == "gmail.com"

def test_primary_sender_returns_none_if_no_email():
    domain = primary_sender_domain(None, "No email addresses here.")
    assert domain is None


# ── Entity extraction ──────────────────────────────────────────────────────────

def test_extract_org_names_corp_suffix():
    text = "On behalf of Apex Technologies Ltd, we are pleased..."
    orgs = extract_org_names(text)
    assert any("Apex" in o for o in orgs)

def test_extract_org_names_welcome():
    text = "Welcome to Globex Corporation! Your start date is..."
    orgs = extract_org_names(text)
    assert any("Globex" in o for o in orgs)

def test_extract_org_names_empty_text():
    orgs = extract_org_names("")
    assert isinstance(orgs, list)
