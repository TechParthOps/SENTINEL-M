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


def analyze_document(path: str, filename: str = "") -> dict:
    """Analyze a document file on disk with bounded memory: PDF tokens are
    scanned in fixed-size streaming chunks; OOXML is inspected via the zip
    central directory without decompressing parts wholesale."""
    result: dict = {"kind": "document", "filename": filename, "status": "unsupported", "findings": []}

    with open(path, "rb") as probe:
        head = probe.read(8)
    if head[:5] == b"%PDF-":
        return _pdf(path, result, filename)
    if head[:4] == b"PK\x03\x04":
        return _office_zip(path, result, filename)
    result["error"] = "unsupported document type (PDF and OOXML zip formats only)"
    return result


PDF_SCAN_CHUNK = 1024 * 1024
PDF_SCAN_OVERLAP = 16  # longest token is 12 bytes — re-scan a small tail per chunk


def _pdf(path: str, result: dict, filename: str) -> dict:
    result["status"] = "analyzed"
    with open(path, "rb") as fh:
        head = fh.read(9)
    result["metadata"] = {"format": "pdf", "version": head[5:9].decode("ascii", "replace")}

    found: dict[str, bool] = {}
    page_count = 0
    prev_tail = b""
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(PDF_SCAN_CHUNK)
            if not chunk:
                break
            buf = prev_tail + chunk
            overlap = len(prev_tail)
            prev_tail = buf[-PDF_SCAN_OVERLAP:]
            page_count += chunk.count(b"/Type /Page") + chunk.count(b"/Type/Page")
            for token, _category, _conf in PDF_TOKENS:
                if token in found:
                    continue
                idx = buf.find(token)
                while idx != -1:
                    if idx + len(token) > overlap:  # hit reaches into the fresh part of this chunk
                        # /AA and /JS are extremely short — require word-ish boundaries
                        # to cut false positives
                        if token in (b"/JS", b"/AA") and not re.match(
                            re.escape(token) + rb"[A-Za-z]{0,2}[^A-Za-z]", buf[idx:idx + len(token) + 3]
                        ):
                            idx = buf.find(token, idx + 1)
                            continue
                        found[token] = True
                        break
                    idx = buf.find(token, idx + 1)
    result["metadata"]["page_count_rough"] = page_count

    for token, category, conf in PDF_TOKENS:
        if not found.get(token):
            continue
        result["findings"].append({
            "category": category,
            "confidence": conf,
            "evidence": f"PDF object {token.decode('ascii', 'replace')} present",
        })
    if found.get(b"/AcroForm") and (found.get(b"/JavaScript") or found.get(b"/JS")):
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


def _office_zip(path: str, result: dict, filename: str) -> dict:
    result["status"] = "analyzed"
    try:
        zf = zipfile.ZipFile(path)
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
    # macro detection overlaps the malware engine's Office check but works on the zip stream
    for name in names:
        if name.endswith(".bin"):
            try:
                info = zf.getinfo(name)
                with zf.open(name) as fh:
                    blob = fh.read(64)
                if b"\x00" in blob[:16] and info.file_size > 64:
                    result["findings"].append({
                        "category": "office_binary_part",
                        "confidence": 0.4,
                        "evidence": f"binary part {name} ({info.file_size} bytes) — review via Malware Analysis",
                    })
            except Exception:
                pass
    result["limitations"] = [
        "OOXML structural scan only; legacy OLE2 (.doc/.xls) documents route to the Malware engine.",
        "OCR is not bundled in this build.",
    ]
    zf.close()
    return result
