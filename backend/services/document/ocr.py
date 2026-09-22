"""
Conditional OCR wrapper.

If pytesseract + Pillow are installed AND tesseract binary is present,
converts each PDF page to image and runs OCR.  Otherwise raises ImportError.
"""
from __future__ import annotations


def is_ocr_available() -> bool:
    """Return True if OCR prerequisites are met."""
    try:
        import pytesseract  # type: ignore
        import PIL  # type: ignore  # noqa: F401
        pytesseract.get_tesseract_version()  # raises if binary missing
        return True
    except Exception:
        return False


def ocr_pdf_bytes(content: bytes) -> str:
    """
    Convert each page of a PDF to an image and run Tesseract OCR.

    Raises ImportError if dependencies are missing.
    """
    import io
    import pypdf  # type: ignore
    from PIL import Image  # type: ignore
    import pytesseract  # type: ignore
    import fitz  # type: ignore  # PyMuPDF – better rendering than pypdf for images

    doc = fitz.open(stream=content, filetype="pdf")
    pages_text: list[str] = []
    for page in doc:
        mat = fitz.Matrix(2, 2)  # 2× zoom for better OCR accuracy
        pix = page.get_pixmap(matrix=mat)
        img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
        pages_text.append(pytesseract.image_to_string(img))

    return "\n".join(pages_text).strip()
