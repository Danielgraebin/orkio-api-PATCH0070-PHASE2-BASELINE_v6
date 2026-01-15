from __future__ import annotations
from typing import Tuple
import io

from pypdf import PdfReader
from docx import Document

MAX_EXTRACT_CHARS = 1_200_000  # safety guard

def _trim(text: str) -> str:
    text = (text or "").replace("\x00", "")
    if len(text) > MAX_EXTRACT_CHARS:
        text = text[:MAX_EXTRACT_CHARS]
    return text

def extract_text(filename: str, content: bytes) -> Tuple[str, int]:
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        reader = PdfReader(io.BytesIO(content))
        parts = []
        for page in reader.pages:
            t = page.extract_text() or ""
            if t:
                parts.append(t)
        text = "\n\n".join(parts)
        text = _trim(text)
        return text, len(text)

    if name.endswith(".docx"):
        doc = Document(io.BytesIO(content))
        parts = [p.text for p in doc.paragraphs if p.text]
        text = "\n".join(parts)
        text = _trim(text)
        return text, len(text)

    # txt/md fallback
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    text = _trim(text)
    return text, len(text)
