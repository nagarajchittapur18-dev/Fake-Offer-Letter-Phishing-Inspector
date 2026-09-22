"""
File ingestion service.
Supports PDF (.pdf), Microsoft Word (.docx), and plain-text/email (.txt/.eml).
"""

import io
from fastapi import UploadFile, HTTPException

MAX_FILE_SIZE = 10 * 1024 * 1024   # 10 MB
ACCEPTED_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "message/rfc822",   # .eml
}
ACCEPTED_EXTENSIONS = {".pdf", ".docx", ".txt", ".eml"}


async def extract_text_from_file(file: UploadFile) -> str:
    """
    Read and return plain text from an uploaded PDF, DOCX, TXT, or EML file.
    Raises HTTPException on bad input; returns a warning string for blank PDFs.
    """
    # ── Size guard ────────────────────────────────────────────────────────────
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(content) / 1_048_576:.1f} MB). Maximum allowed size is 10 MB.",
        )

    filename  = (file.filename or "").lower()
    extension = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

    if extension not in ACCEPTED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{extension}'. Accepted formats: PDF, DOCX, TXT, EML.",
        )

    # ── PDF ───────────────────────────────────────────────────────────────────
    if extension == ".pdf":
        return _extract_pdf(content)

    # ── DOCX ──────────────────────────────────────────────────────────────────
    if extension == ".docx":
        return _extract_docx(content)

    # ── TXT / EML (raw UTF-8) ─────────────────────────────────────────────────
    try:
        return content.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Could not decode file as UTF-8: {exc}")


def _extract_pdf(content: bytes) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(content))
        pages  = [page.extract_text() or "" for page in reader.pages]
        text   = "\n".join(pages).strip()
        if not text:
            return (
                "[WARNING: No extractable text found in this PDF. "
                "It may be a scanned image-only document. "
                "Please paste the text manually for accurate analysis.]"
            )
        return text
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse PDF: {exc}")


def _extract_docx(content: bytes) -> str:
    try:
        import docx
        doc   = docx.Document(io.BytesIO(content))
        lines = [p.text for p in doc.paragraphs if p.text.strip()]
        return "\n".join(lines)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=f"Failed to parse DOCX: {exc}")
