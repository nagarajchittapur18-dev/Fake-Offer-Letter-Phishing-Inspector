"""
EML / RFC-2822 email file parser.

Extracts:
  - From address
  - Reply-To address
  - Subject
  - All headers
  - Plain-text body
  - Embedded URLs
  - Attachments summary
"""
from __future__ import annotations

import email
import re
from email.header import decode_header
from typing import Optional


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _decode_header_str(raw: Optional[str]) -> str:
    if not raw:
        return ""
    parts = decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(part)
    return "".join(decoded)


def parse_eml(content: bytes) -> tuple[str, dict]:
    """
    Parse an EML file.

    Returns (body_text, metadata).
    metadata keys: from, reply_to, subject, date, message_id,
                   headers, embedded_urls, attachments, has_reply_to_mismatch
    """
    msg = email.message_from_bytes(content)

    from_raw    = _decode_header_str(msg.get("From", ""))
    reply_to    = _decode_header_str(msg.get("Reply-To", ""))
    subject     = _decode_header_str(msg.get("Subject", ""))
    date_str    = msg.get("Date", "")
    message_id  = msg.get("Message-ID", "")

    # Extract all headers as dict
    headers: dict = {}
    for key in set(msg.keys()):
        headers[key] = _decode_header_str(msg.get(key, ""))

    # Collect body parts
    body_parts: list[str] = []
    attachments: list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            cd = str(part.get("Content-Disposition", ""))
            if "attachment" in cd.lower():
                fname = part.get_filename() or "unknown"
                attachments.append(fname)
            elif ct == "text/plain":
                try:
                    charset = part.get_content_charset() or "utf-8"
                    body_parts.append(part.get_payload(decode=True).decode(charset, errors="replace"))
                except Exception:
                    pass
            elif ct == "text/html" and not body_parts:
                try:
                    charset = part.get_content_charset() or "utf-8"
                    html = part.get_payload(decode=True).decode(charset, errors="replace")
                    # Strip HTML tags for plain text
                    body_parts.append(re.sub(r"<[^>]+>", " ", html))
                except Exception:
                    pass
    else:
        try:
            charset = msg.get_content_charset() or "utf-8"
            payload = msg.get_payload(decode=True)
            if payload:
                body_parts.append(payload.decode(charset, errors="replace"))
        except Exception:
            body_parts.append(str(msg.get_payload()))

    body = "\n".join(body_parts).strip()

    # Extract embedded URLs
    embedded_urls = list(set(_URL_RE.findall(body)))

    # Detect Reply-To mismatch (different domain than From)
    has_reply_to_mismatch = False
    if reply_to and from_raw:
        from_domain    = _extract_domain_from_email(from_raw)
        replyto_domain = _extract_domain_from_email(reply_to)
        if from_domain and replyto_domain and from_domain != replyto_domain:
            has_reply_to_mismatch = True

    metadata = {
        "from":                 from_raw,
        "reply_to":             reply_to,
        "subject":              subject,
        "date":                 date_str,
        "message_id":           message_id,
        "headers":              headers,
        "embedded_urls":        embedded_urls,
        "attachments":          attachments,
        "has_reply_to_mismatch": has_reply_to_mismatch,
        "from_domain":          _extract_domain_from_email(from_raw),
        "reply_to_domain":      _extract_domain_from_email(reply_to) if reply_to else None,
    }

    # Prepend headers as readable context
    header_block = f"From: {from_raw}\nReply-To: {reply_to}\nSubject: {subject}\nDate: {date_str}\n\n"
    return header_block + body, metadata


def _extract_domain_from_email(addr: str) -> Optional[str]:
    match = re.search(r"@([\w\.-]+)", addr)
    if match:
        return match.group(1).lower().rstrip(".,!?;:")
    return None
