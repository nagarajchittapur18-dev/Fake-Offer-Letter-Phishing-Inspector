"""
PDF text extraction with optional OCR fallback.
"""
from __future__ import annotations

import io
from typing import Optional


def extract_pdf(content: bytes) -> tuple[str, dict]:
    """
    Extract text from PDF bytes.

    Returns (text, metadata) where metadata includes page count, has_images, ocr_used.
    Falls back to OCR if pypdf finds no text (scanned PDF).
    """
    metadata: dict = {
        "page_count": 0,
        "has_text_layer": False,
        "ocr_used": False,
        "ocr_available": False,
        "author": None,
        "creator": None,
        "producer": None,
        "title": None,
        "created": None,
    }

    try:
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(io.BytesIO(content))
        metadata["page_count"] = len(reader.pages)

        # Extract document metadata
        if reader.metadata:
            md = reader.metadata
            metadata["author"]   = md.get("/Author")
            metadata["creator"]  = md.get("/Creator")
            metadata["producer"] = md.get("/Producer")
            metadata["title"]    = md.get("/Title")
            metadata["created"]  = md.get("/CreationDate")

        pages = [page.extract_text() or "" for page in reader.pages]
        text  = "\n".join(pages).strip()

        if text:
            metadata["has_text_layer"] = True
            return text, metadata

    except Exception as exc:
        raise ValueError(f"Failed to parse PDF: {exc}") from exc

    # ── Scanned PDF: attempt OCR ───────────────────────────────────────────────
    try:
        from .ocr import ocr_pdf_bytes  # type: ignore
        ocr_text = ocr_pdf_bytes(content)
        if ocr_text:
            metadata["ocr_used"] = True
            metadata["ocr_available"] = True
            return ocr_text, metadata
    except ImportError:
        pass
    except Exception:
        pass

    return (
        "[WARNING: No extractable text found in this PDF. "
        "It may be a scanned image. "
        "OCR is not available on this server — please paste the text manually.]",
        metadata,
    )
