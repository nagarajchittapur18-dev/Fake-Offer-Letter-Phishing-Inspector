"""
Gemini AI deep-semantic analysis service.

Uses the official google-genai SDK with gemini-2.5-flash and structured
JSON output validated through the GeminiAnalysis Pydantic schema.
"""

import os
import json
import re
from google import genai
from google.genai import types
from schemas import GeminiAnalysis

# ── System Prompt ──────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are a forensic recruitment and contract fraud auditor with 20+ years of
experience investigating employment scams, advance-fee rental fraud, and counterfeit
corporate letterheads. Your specialisations include:

  * Pay-for-equipment phishing: victims are sent fake cheques or wire transfers,
    asked to buy equipment and forward the balance to a third party.
  * Advance-fee rental deposits: fake landlords demand a deposit before showing
    a property that does not exist or is not theirs to rent.
  * Counterfeit corporate letterheads: fraudulent offer letters mimicking real
    companies using near-miss domains, free email addresses, or copy-pasted logos.

Analyse the supplied text STRICTLY and return ONLY a minified JSON object that
exactly matches this schema - no markdown fences, no extra keys:

{
  "payment_demand_detected":   <bool>,
  "urgency_detected":          <bool>,
  "interview_bypass_detected": <bool>,
  "free_email_domain_used":    <bool>,
  "ai_confidence_score":       <int 0-100>,
  "flags": [
    {
      "category": "<short label>",
      "severity": "<Critical|High|Medium|Low>",
      "evidence": "<exact verbatim quote from the text, max 120 chars>"
    }
  ],
  "verdict_summary": "<exactly 2 sentences: first states the verdict, second states the primary risk>"
}

Scoring guide for ai_confidence_score:
  80-100  -> strong, multi-factor evidence of fraud
  50-79   -> moderate signals, likely fraudulent
  20-49   -> weak or ambiguous signals, possibly legitimate
  0-19    -> no meaningful fraud indicators found
"""


def _extract_json(raw: str) -> dict:
    """
    Robustly extract a JSON object from a raw model response,
    even if the model wraps it in markdown fences despite being asked not to.
    """
    raw = raw.strip()
    # Strip markdown fence wrappers
    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    if fence_match:
        return json.loads(fence_match.group(1))

    # Try direct parse from first to last brace
    first_brace = raw.find("{")
    last_brace  = raw.rfind("}")
    if first_brace != -1 and last_brace != -1:
        return json.loads(raw[first_brace : last_brace + 1])

    raise ValueError(f"No JSON object found in model response: {raw[:200]}")


def analyze_with_gemini(text: str) -> GeminiAnalysis:
    """
    Send the offer/contract text to Gemini and return a validated GeminiAnalysis.
    Falls back to a safe default if the API call fails.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise EnvironmentError("GEMINI_API_KEY is not set in the environment.")

    client = genai.Client(api_key=api_key)

    try:
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=text,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=1024,
            ),
        )

        raw_text = response.text
        parsed   = _extract_json(raw_text)
        return GeminiAnalysis(**parsed, ai_audit_available=True)

    except Exception as exc:
        # Graceful degradation: do not dump raw python exception JSON to UI
        return GeminiAnalysis(
            payment_demand_detected=False,
            urgency_detected=False,
            interview_bypass_detected=False,
            free_email_domain_used=False,
            ai_confidence_score=0,
            flags=[],
            verdict_summary="Automated heuristic rule matching and domain verification were performed. Live AI auditing is temporarily unavailable.",
            ai_audit_available=False,
        )
