"""
Gemini AI deep-semantic analysis service.

Model is configurable via GEMINI_MODEL env var (default: gemini-2.0-flash).
All API errors produce a graceful AIAnalysis with available=False.
"""
from __future__ import annotations

import json
import os
import re

from schemas import AIAnalysis


SYSTEM_PROMPT = """You are a forensic employment-fraud and phishing auditor with 20+ years experience.

Analyse the supplied document text and return ONLY a minified JSON object — no markdown fences:

{
  "payment_demand_detected":   <bool>,
  "urgency_detected":          <bool>,
  "interview_bypass_detected": <bool>,
  "free_email_domain_used":    <bool>,
  "ai_confidence_score":       <int 0-100>,
  "semantic_flags":            ["<short phrase describing each detected risk>"],
  "verdict_summary":           "<exactly 2 sentences: first states the risk level verdict, second states the primary reason>"
}

Scoring guide for ai_confidence_score:
  80-100 → strong multi-factor evidence of fraud
  50-79  → moderate signals, likely fraudulent
  20-49  → weak or ambiguous signals, possibly legitimate
  0-19   → no meaningful fraud indicators found

Use neutral, evidence-based language. Never say "100% scam" — say "high risk" or "strong indicators of fraud".
"""


def _extract_json(raw: str) -> dict:
    raw = raw.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence:
        return json.loads(fence.group(1))
    first = raw.find("{")
    last  = raw.rfind("}")
    if first != -1 and last != -1:
        return json.loads(raw[first : last + 1])
    raise ValueError(f"No JSON in model response: {raw[:200]}")


def _fallback(reason: str) -> AIAnalysis:
    return AIAnalysis(
        available=False,
        model=None,
        confidence_score=0,
        score_contribution=0,
        verdict_summary=f"AI audit unavailable — heuristics applied. ({reason})",
        semantic_flags=[],
    )


def analyze_with_gemini(text: str) -> AIAnalysis:
    """
    Analyse text with Gemini.  Returns AIAnalysis with available=False on any error.
    """
    api_key = os.getenv("GEMINI_API_KEY", "")
    if not api_key:
        return _fallback("GEMINI_API_KEY not set")

    model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

    try:
        from google import genai  # type: ignore
        from google.genai import types  # type: ignore

        client   = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=text[:40_000],  # guard against very long inputs
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=1024,
            ),
        )
        parsed = _extract_json(response.text)

        confidence  = int(parsed.get("ai_confidence_score", 0))
        # Translate confidence to score contribution (max 5)
        if confidence >= 80:
            contrib = 5
        elif confidence >= 50:
            contrib = 3
        elif confidence >= 20:
            contrib = 1
        else:
            contrib = 0

        return AIAnalysis(
            available=True,
            model=model_name,
            confidence_score=confidence,
            score_contribution=contrib,
            verdict_summary=parsed.get("verdict_summary", ""),
            semantic_flags=parsed.get("semantic_flags", []),
        )

    except Exception as exc:
        return _fallback(str(exc)[:120])
