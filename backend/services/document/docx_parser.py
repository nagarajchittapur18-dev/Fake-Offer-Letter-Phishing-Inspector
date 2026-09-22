"""
DOCX text extraction with metadata.
"""
from __future__ import annotations

import io


def extract_docx(content: bytes) -> tuple[str, dict]:
    """
    Extract text and metadata from a DOCX file.

    Returns (text, metadata).
    """
    metadata: dict = {
        "author":       None,
        "last_modified_by": None,
        "created":      None,
        "modified":     None,
        "title":        None,
        "subject":      None,
        "description":  None,
        "paragraph_count": 0,
    }

    try:
        import docx  # type: ignore
        doc = docx.Document(io.BytesIO(content))

        # Core properties
        try:
            cp = doc.core_properties
            metadata["author"]           = cp.author
            metadata["last_modified_by"] = cp.last_modified_by
            metadata["created"]          = cp.created.isoformat() if cp.created else None
            metadata["modified"]         = cp.modified.isoformat() if cp.modified else None
            metadata["title"]            = cp.title
            metadata["subject"]          = cp.subject
            metadata["description"]      = cp.description
        except Exception:
            pass

        lines = [p.text for p in doc.paragraphs if p.text.strip()]
        metadata["paragraph_count"] = len(lines)
        return "\n".join(lines), metadata

    except Exception as exc:
        raise ValueError(f"Failed to parse DOCX: {exc}") from exc
