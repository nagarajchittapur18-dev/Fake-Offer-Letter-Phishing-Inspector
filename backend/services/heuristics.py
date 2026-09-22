import re

def analyze_text(text: str, domain: str | None = None) -> dict:
    """
    Regex scan for high-risk employment scam patterns.
    """
    text_lower = text.lower()
    findings = []
    penalty = 0

    # 1. Payment demands
    payment_keywords = [
        r'\bcheck\b', r'\bcheque\b', r'\bzelle\b', r'\bcashapp\b', r'\bcrypto\b', 
        r'\bwestern union\b', r'\bwire transfer\b', r'\bprocessing fee\b', 
        r'\bbackground check fee\b', r'\bequipment purchase\b', r'\breimbursement\b'
    ]
    
    payment_matches = [p for p in payment_keywords if re.search(p, text_lower)]
    if payment_matches:
        penalty += 30
        findings.append("Detected high-risk payment/fee requests (e.g., checks, wire transfer, equipment purchase).")

    # 2. Channel red flags
    channel_keywords = [
        r'\btelegram\b', r'\bwhatsapp\b', r'\bsignal\b', r'\bimmediate hire\b', 
        r'\bwithout interview\b', r'\bno interview\b'
    ]
    
    channel_matches = [p for p in channel_keywords if re.search(p, text_lower)]
    if channel_matches:
        penalty += 30
        findings.append("Detected informal communication channels or interview bypass claims (Telegram, WhatsApp, Signal, immediate hire).")

    # 3. Domain spoofing
    free_email_domains = ['gmail.com', 'hotmail.com', 'yahoo.com', 'outlook.com', 'aol.com', 'proton.me', 'protonmail.com']
    if domain and domain.lower() in free_email_domains:
        penalty += 25
        findings.append(f"Sender uses a free email provider ({domain}) which is highly unusual for legitimate corporate recruitment.")

    return {
        "heuristics_penalty": penalty,
        "findings": findings
    }
