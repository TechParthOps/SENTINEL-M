"""Document analysis pipeline (Phase 3): PDF structure scan + Office (zip) inspection.

Deterministic structural indicators only. OCR is NOT bundled (no tesseract binary
guaranteed) and is reported as an honest limitation rather than faked.
"""
from __future__ import annotations

import re
import zipfile

PDF_TOKENS = [
    (b"/JavaScript", "pdf_javascript", 0.85),
    (b"/JS", "pdf_js_short", 0.6),
    (b"/OpenAction", "pdf_open_action", 0.7),
    (b"/Launch", "pdf_launch_action", 0.8),
    (b"/EmbeddedFile", "pdf_embedded_file", 0.6),
    (b"/AA", "pdf_additional_actions", 0.4),
    (b"/Encrypt", "pdf_encrypted", 0.2),
    (b"/URI", "pdf_uri_actions", 0.2),
]

OFFICE_DANGEROUS_PARTS = [
    ("vbaProject.bin", "office_vba_macros", 0.85),
    ("externalLink", "office_external_links", 0.5),
    ("oleObject", "office_ole_object", 0.7),
]


def analyze_document(data: bytes, filename: str = "") -> dict:
    result: dict = {"kind": "document", "filename": filename, "status": "unsupported", "findings": []}

    if data[:5] == b"%PDF-":
        return _pdf(data, result, filename)
    if data[:4] == b"PK\x03\x04":
        return _office_zip(data, result, filename)
    result["error"] = "unsupported document type (PDF and OOXML zip formats only)"
    return result


def _pdf(data: bytes, result: dict, filename: str) -> dict:
    result["status"] = "analyzed"
    result["metadata"] = {"format": "pdf", "version": data[5:9].decode("ascii", "replace")}
    pages = data.count(b"/Type /Page") or data.count(b"/Type/Page")
    result["metadata"]["page_count_rough"] = pages
    for token, category, conf in PDF_TOKENS:
        if token in data:
            # /AA and /JS are extremely short — require word-ish boundaries to cut false positives
            if token in (b"/JS", b"/AA") and not re.search(re.escape(token) + rb"[A-Za-z]{0,2}[^A-Za-z]", data):
                continue
            result["findings"].append({
                "category": category,
                "confidence": conf,
                "evidence": f"PDF object {token.decode('ascii', 'replace')} present",
            })
    if b"/AcroForm" in data and (b"/JavaScript" in data or b"/JS" in data):
        result["findings"].append({
            "category": "pdf_form_with_scripts",
            "confidence": 0.8,
            "evidence": "AcroForm combined with JavaScript objects",
        })
    result["limitations"] = [
        "Structural scan only: presence of script/action objects is an indicator, not proof of malicious use.",
        "OCR is not bundled in this build — text extraction from scanned PDFs is not available.",
    ]
    return result


def _office_zip(data: bytes, result: dict, filename: str) -> dict:
    import io

    result["status"] = "analyzed"
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
    except Exception as exc:
        result["error"] = f"zip open failed: {type(exc).__name__}"
        return result
    result["metadata"] = {"format": "ooxml", "parts": len(names)}
    for part, category, conf in OFFICE_DANGEROUS_PARTS:
        hit = [n for n in names if part in n]
        if hit:
            result["findings"].append({
                "category": category,
                "confidence": conf,
                "evidence": f"OOXML part(s): {hit[:3]}",
            })
    # macro detection overlaps the malware engine's Office check but works on raw bytes
    for name in names:
        if name.endswith(".bin"):
            try:
                blob = zf.read(name)
                if b"\x00" in blob[:16] and len(blob) > 64:
                    result["findings"].append({
                        "category": "office_binary_part",
                        "confidence": 0.4,
                        "evidence": f"binary part {name} ({len(blob)} bytes) — review via Malware Analysis",
                    })
            except Exception:
                pass
    result["limitations"] = [
        "OOXML structural scan only; legacy OLE2 (.doc/.xls) documents route to the Malware engine.",
        "OCR is not bundled in this build.",
    ]
    return result
