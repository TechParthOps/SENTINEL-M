"""Multimodal analysis orchestrator (Phase 3).

Routes submitted files to the right pipeline by magic signature. Files are
analyzed by STREAMING from disk (path-based pipelines, fixed-size reads) and
NEVER retained (ADR-011) — only the analysis record (hashes + result) is stored.
There is deliberately NO file-size cap: every pipeline reads bounded chunks.

Honest scope of this build:
  images  — metadata/EXIF, generative-AI tool strings, QR payloads, recompression probe
  audio   — WAV/PCM statistics only (MP3/OGG unsupported → reported as such)
  video   — OpenCV-decodable containers; frame statistics (no neural detectors)
  document— PDF structural scan + OOXML zip inspection (no OCR)
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.multimodal.document import analyze_document
from app.multimodal.image import analyze_image
from app.multimodal.audio import analyze_audio
from app.multimodal.models import MediaAnalysis
from app.multimodal.video import analyze_video

IMAGE_MAGICS = [(b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"BM", "bmp")]
DOCUMENT_MAGICS = [(b"%PDF-", "pdf"), (b"PK\x03\x04", "ooxml")]
AUDIO_MAGICS = [(b"RIFF", "wav"), (b"ID3", "mp3"), (b"OggS", "ogg")]
VIDEO_MAGICS = [(b"ftyp", "mp4"), (b"\x1a\x45\xdf\xa3", "mkv"), (b"RIFF", "avi")]

_HASH_CHUNK = 1024 * 1024


def detect_kind_head(head: bytes) -> str:
    """Classify by the first bytes of a file."""
    for magic, _kind in IMAGE_MAGICS:
        if head.startswith(magic):
            return "image"
    for magic, kind in DOCUMENT_MAGICS:
        if head.startswith(magic):
            return "document"
    for magic, _ in AUDIO_MAGICS:
        if head.startswith(magic):
            return "audio"
    if head[4:8] == b"ftyp" or head.startswith(VIDEO_MAGICS[1][0]):
        return "video"
    if head.startswith(b"RIFF") and head[8:12] == b"AVI ":
        return "video"
    return "unknown"


def detect_kind(data: bytes) -> str:
    """Compatibility wrapper for in-memory buffers."""
    return detect_kind_head(data[:16])


VERDICTS = {"clean": "clean", "indicators_only": "indicators_only", "high_risk": "high_risk",
            "unsupported": "unsupported"}


def _hash_file(path: str) -> tuple[str, str]:
    sha256, md5 = hashlib.sha256(), hashlib.md5()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(_HASH_CHUNK)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


class MultimodalEngine:
    def analyze_path(self, path: str, filename: str = "") -> dict:
        """Analyze any file on disk with bounded memory (streaming reads)."""
        with open(path, "rb") as fh:
            head = fh.read(16)
        kind = detect_kind_head(head)
        sha256, md5 = _hash_file(path)
        base = {"size": os.path.getsize(path), "sha256": sha256, "md5": md5}
        if kind == "image":
            result = analyze_image(path, filename)
        elif kind == "audio":
            result = analyze_audio(path, filename)
        elif kind == "video":
            result = analyze_video(path, filename)
        elif kind == "document":
            result = analyze_document(path, filename)
        else:
            result = {"kind": "unknown", "status": "unsupported",
                      "error": "unrecognized file type — analysis pipeline not available for this format"}
        result.update(base)
        risk = max((f.get("confidence", 0.0) for f in result.get("findings", [])), default=0.0)
        result["risk_score"] = round(risk, 3)
        result["verdict"] = (
            "unsupported" if result.get("status") == "unsupported"
            else "high_risk" if risk >= 0.8
            else "indicators_only" if result.get("findings")
            else "clean"
        )
        return result

    def analyze(self, data: bytes, filename: str = "") -> dict:
        """Compatibility wrapper: spool an in-memory buffer to disk and stream it."""
        suffix = os.path.splitext(filename or "media.bin")[1] or ".bin"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
            tf.write(data)
            tmp_path = tf.name
        try:
            return self.analyze_path(tmp_path, filename)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    def save(self, db: Session, result: dict, actor: str) -> MediaAnalysis:
        row = MediaAnalysis(
            id=str(uuid.uuid4()),
            kind=str(result.get("kind", "unknown"))[:32],
            filename=str(result.get("filename", ""))[:255],
            sha256=result["sha256"],
            md5=result["md5"],
            size=result["size"],
            mime=str(result.get("metadata", {}).get("format", ""))[:64],
            status=result.get("status", "analyzed")[:32],
            risk_score=result["risk_score"],
            verdict=result["verdict"],
            result=result,
            submitted_by=actor[:128],
        )
        result["analysis_id"] = row.id
        row.result = result
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    def list_analyses(self, db: Session, limit: int = 100) -> list[dict]:
        rows = db.query(MediaAnalysis).order_by(MediaAnalysis.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id, "kind": r.kind, "filename": r.filename, "sha256": r.sha256,
                "size": r.size, "mime": r.mime, "status": r.status,
                "risk_score": r.risk_score, "verdict": r.verdict,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "submitted_by": r.submitted_by,
            }
            for r in rows
        ]

    def health(self) -> dict:
        return {
            "status": "ok",
            "pipelines": ["image", "audio(wav)", "video(opencv-decodable)", "document(pdf/ooxml)"],
            "ocr": "not bundled in this build (no tesseract binary) — reported honestly",
            "byte_retention": False,
            "max_file_size": "unlimited (streamed analysis)",
        }


multimodal_engine = MultimodalEngine()
