"""Image analysis pipeline (Phase 3). Deterministic + heuristic; no external services.

- Metadata & EXIF (format, dimensions, software fields incl. generative-AI tool strings)
- QR code detection (OpenCV) with payload threat analysis (URL schemes, shorteners,
  IP-literal hosts, punycode, WIFI/sms payloads)
- Manipulation indicators: error-level-lite (recompression difference) and metadata gaps —
  explicitly PROBABILISTIC with low confidence; never an authenticity verdict.
- OCR: intentionally not bundled (no tesseract binary guaranteed) — status reported honestly.
"""
from __future__ import annotations

import re

GENAI_SOFTWARE_MARKERS = [
    "dall", "midjourney", "stable", "diffusion", "firefly", "imagen", "sora", "veo",
    "flux", "comfyui", "automatic1111", "generative",
]

SHORTENERS = ("bit.ly", "t.co", "goo.gl", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "ow.ly")


def analyze_image(path: str, filename: str = "") -> dict:
    """Analyze an image file on disk. Pixels are decoded lazily by PIL; the raw
    file is never fully buffered."""
    result: dict = {"kind": "image", "filename": filename, "status": "analyzed"}
    findings: list[dict] = []

    try:
        from PIL import Image, ImageChops

        img = Image.open(path)
        img.load()
    except Exception as exc:
        result["status"] = "unsupported"
        result["error"] = f"image decode failed: {type(exc).__name__}"
        return result

    result["metadata"] = {
        "format": img.format,
        "width": img.width,
        "height": img.height,
        "mode": img.mode,
        "animated": getattr(img, "is_animated", False),
        "frames": getattr(img, "n_frames", 1),
    }
    exif = {}
    try:
        raw_exif = img.getexif()
        exif = {str(k): str(v)[:120] for k, v in raw_exif.items()}
    except Exception:
        pass
    result["exif"] = {"present": bool(exif), "tags": exif}

    # generative-AI tool strings in metadata
    blob = " ".join(exif.values()).lower()
    genai_hits = [m for m in GENAI_SOFTWARE_MARKERS if m in blob]
    if genai_hits:
        findings.append({
            "category": "synthetic_image_metadata",
            "confidence": 0.95,
            "evidence": f"generative-AI tool string in metadata: {genai_hits}",
            "note": "metadata marker, not pixel-level evidence",
        })

    # metadata gaps (weak, probabilistic)
    if img.format == "JPEG" and not exif:
        findings.append({
            "category": "metadata_absent",
            "confidence": 0.2,
            "evidence": "JPEG without EXIF (common in recompressed/generated images; also normal after stripping)",
            "note": "weak indicator only",
        })

    # error-level-lite: recompression difference between luminance planes
    try:
        ela = _ela_lite(img)
        result["ela"] = ela
        if ela["mean_difference"] > 18.0:
            findings.append({
                "category": "recompression_variance_high",
                "confidence": min(0.5, ela["mean_difference"] / 200.0),
                "evidence": f"recompression mean difference {ela['mean_difference']:.1f} (mixed-quality regions possible)",
                "note": "probabilistic indicator — not evidence of tampering",
            })
    except Exception:
        pass

    # QR detection + payload analysis
    qr = _qr_analysis(path)
    result["qr"] = qr
    for f in qr.get("findings", []):
        findings.append(f)

    result["findings"] = findings
    result["limitations"] = [
        "Heuristic indicators only; no image can be certified authentic or synthetic from metadata alone.",
        "OCR is not bundled in this build (no tesseract binary) — text extraction from images is not available.",
    ]
    return result


def _ela_lite(img) -> dict:
    """Recompress at lower quality and measure per-pixel difference statistics."""
    import io
    import numpy as np
    from PIL import Image, ImageChops

    gray = img.convert("L").resize((min(512, img.width), min(512, img.height)))
    buf = io.BytesIO()
    gray.save(buf, format="JPEG", quality=70)
    buf.seek(0)
    recompressed = Image.open(buf).convert("L")
    diff = np.asarray(ImageChops.difference(gray, recompressed), dtype=np.float64)
    return {
        "mean_difference": round(float(diff.mean()), 2),
        "max_difference": int(diff.max()),
        "note": "single recompression probe; robust ELA needs more probes — indicator only",
    }


def _qr_analysis(path: str) -> dict:
    out: dict = {"found": False, "findings": []}
    try:
        import cv2

        img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
        if img is None:
            return out
        detector = cv2.QRCodeDetector()

        def _decode(image):
            try:
                return detector.detectAndDecode(image)[0]
            except cv2.error:
                return ""

        text = _decode(img)
        if not text:
            # small/synthetic QR images need upscaling (nearest-neighbor keeps modules crisp)
            h, w = img.shape[:2]
            scale = max(1, min(16, 1024 // max(h, w)))
            if scale > 1:
                text = _decode(cv2.resize(img, (w * scale, h * scale),
                                          interpolation=cv2.INTER_NEAREST))
        if not text:
            # add a quiet zone before a final attempt
            big = cv2.copyMakeBorder(img, 48, 48, 48, 48, cv2.BORDER_CONSTANT, value=255)
            text = _decode(big)
        if not text:
            return out
        out["found"] = True
        out["payload"] = text[:400]
        findings = _qr_payload_findings(text)
        out["findings"] = findings
        return out
    except Exception as exc:  # cv2 unavailable or decode failure
        out["error"] = f"QR analysis unavailable: {type(exc).__name__}"
        return out


def _qr_payload_findings(payload: str) -> list[dict]:
    findings: list[dict] = []
    low = payload.lower()

    m = re.match(r"https?://([^/\s]+)", low)
    if m:
        host = m.group(1)
        if any(host == s or host.endswith("." + s) for s in SHORTENERS):
            findings.append({"category": "qr_shortener_url", "confidence": 0.55,
                             "evidence": f"QR points at URL shortener {host}"})
        if re.match(r"\d{1,3}(\.\d{1,3}){3}$", host):
            findings.append({"category": "qr_ip_literal_url", "confidence": 0.6,
                             "evidence": f"QR points at IP-literal host {host}"})
        if "xn--" in host:
            findings.append({"category": "qr_punycode_host", "confidence": 0.6,
                             "evidence": f"QR host uses punycode: {host}"})
    elif low.startswith(("wifi:", "sms:", "tel:", "mailto:", "file:", "data:")):
        findings.append({"category": "qr_non_web_scheme", "confidence": 0.5,
                         "evidence": f"QR uses non-web scheme: {payload.split(':')[0]}"})
    elif not payload.strip():
        pass
    if re.search(r"(?:login|verify|auth|password|account)", low) and m:
        findings.append({"category": "qr_credential_lure", "confidence": 0.5,
                         "evidence": "QR URL contains credential/verification keywords"})
    return findings
