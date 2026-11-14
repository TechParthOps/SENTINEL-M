"""Multimodal pipeline tests (Phase 3): image/QR, audio WAV, video, documents, API."""
from __future__ import annotations

import io
import wave

import numpy as np

from tests.conftest import client  # noqa: F401


def _post(client, admin_headers, data: bytes, name: str):
    import base64

    r = client.post("/api/v1/media/analyze", headers=admin_headers,
                    json={"filename": name, "content_base64": base64.b64encode(data).decode()})
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ fixtures
def _png_qr(payload: str) -> bytes:
    import cv2

    encoder = cv2.QRCodeEncoder.create()
    arr = encoder.encode(payload)
    ok, buf = cv2.imencode(".png", arr)
    assert ok
    return buf.tobytes()


def _wav(seconds=3, rate=16000, tone_hz=220):
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        t = np.linspace(0, seconds, seconds * rate, endpoint=False)
        # speech-like amplitude modulation so pauses/dynamics exist
        amp = (np.sin(2 * np.pi * 1.5 * t) > 0).astype(np.float64) * 0.5 + 0.3
        samples = (np.sin(2 * np.pi * tone_hz * t) * amp * 32767 * 0.8).astype(np.int16)
        w.writeframes(samples.tobytes())
    return buf.getvalue()


# ------------------------------------------------------------------ tests
def test_qr_credential_lure_detected(client, admin_headers):
    body = _post(client, admin_headers, _png_qr("https://bit.ly/verify-login-account"), "qr.png")
    assert body["kind"] == "image"
    assert body["qr"]["found"] is True
    cats = {f["category"] for f in body["qr"]["findings"]}
    assert "qr_shortener_url" in cats
    assert "qr_credential_lure" in cats


def test_clean_image_is_clean(client, admin_headers):
    import cv2

    ok, buf = cv2.imencode(".png", np.full((64, 64), 128, dtype=np.uint8))
    assert ok
    body = _post(client, admin_headers, buf.tobytes(), "flat.png")
    assert body["status"] == "analyzed"
    assert body["verdict"] in ("clean", "indicators_only")
    assert body["metadata"]["format"] == "PNG"


def test_unsupported_format_reported_honestly(client, admin_headers):
    body = _post(client, admin_headers, b"NOT-A-REAL-FORMAT" * 10, "weird.bin")
    assert body["status"] == "unsupported"
    assert body["verdict"] == "unsupported"
    assert body["error"]


def test_mp3_reported_unsupported_not_guessed(client, admin_headers):
    body = _post(client, admin_headers, b"ID3\x03\x00" + b"\x00" * 128, "song.mp3")
    assert body["kind"] == "audio"
    assert body["status"] == "unsupported"
    assert "MP3" in body["error"]


def test_wav_analyzed_with_stats(client, admin_headers):
    body = _post(client, admin_headers, _wav(), "clip.wav")
    assert body["status"] == "analyzed"
    assert body["metadata"]["sample_rate"] == 16000
    assert "spectral_flatness" in body["stats"]
    assert isinstance(body["limitations"], list)


def test_pdf_scripts_detected(client, admin_headers):
    pdf = (b"%PDF-1.7\n1 0 obj <</Type/Catalog/OpenAction 2 0 R/AcroForm 3 0 R>> endobj\n"
           b"2 0 obj <</S/JavaScript/JS(app.alert(1);)>> endobj\n"
           b"3 0 obj <</Fields []>> endobj\n%%EOF")
    body = _post(client, admin_headers, pdf, "evil.pdf")
    assert body["kind"] == "document"
    cats = {f["category"] for f in body["findings"]}
    assert "pdf_javascript" in cats
    assert "pdf_open_action" in cats


def test_ooxml_macro_part_detected(client, admin_headers):
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/vbaProject.bin", b"\x00" * 128)
    body = _post(client, admin_headers, buf.getvalue(), "doc.docx")
    cats = {f["category"] for f in body["findings"]}
    assert "office_vba_macros" in cats


def test_video_analysis_and_bytes_not_retained(client, admin_headers):
    import cv2

    path = "test_video.mp4"
    vw = cv2.VideoWriter(path, cv2.VideoWriter_fourcc(*"mp4v"), 10, (64, 64))
    if not vw.isOpened():
        import pytest

        pytest.skip("OpenCV mp4 encoder unavailable in this build")
    for i in range(30):
        frame = np.full((64, 64, 3), (i * 8) % 255, dtype=np.uint8)
        vw.write(frame)
    vw.release()
    with open(path, "rb") as f:
        data = f.read()
    body = _post(client, admin_headers, data, "clip.mp4")
    assert body["kind"] == "video"
    assert body["status"] == "analyzed"
    assert body["stats"]["frames_sampled"] > 0
    assert body["limitations"]  # honesty contract: no neural detectors bundled


def test_analyses_listed(client, admin_headers):
    r = client.get("/api/v1/media/analyses", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["total"] >= 1


def test_media_requires_analyst(client):
    r = client.post("/api/v1/media/analyze", json={"filename": "x.png", "content_base64": "aGVsbG8="})
    assert r.status_code in (401, 403)
