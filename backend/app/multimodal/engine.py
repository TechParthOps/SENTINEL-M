"""Multimodal analysis orchestrator (Phase 3).

Routes submitted bytes to the right pipeline by magic signature. Bytes are analyzed in
memory and NEVER retained (ADR-011) — only the analysis record (hashes + result) is stored.

Honest scope of this build:
  images  — metadata/EXIF, generative-AI tool strings, QR payloads, recompression probe
  audio   — WAV/PCM statistics only (MP3/OGG unsupported → reported as such)
  video   — OpenCV-decodable containers; Haar face-region statistics (no neural detectors)
  document— PDF structural scan + OOXML zip inspection (no OCR)
"""
from __future__ import annotations

import hashlib
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


def detect_kind(data: bytes) -> str:
    for magic, _kind in IMAGE_MAGICS:
        if data.startswith(magic):
            return "image"
    for magic, kind in DOCUMENT_MAGICS:
        if data.startswith(magic):
            return "document"
    for magic, _ in AUDIO_MAGICS:
        if data.startswith(magic):
            return "audio"
    if data[4:8] == b"ftyp" or data.startswith(VIDEO_MAGICS[1][0]):
        return "video"
    if data.startswith(b"RIFF") and data[8:12] == b"AVI ":
        return "video"
    return "unknown"


VERDICTS = {"clean": "clean", "indicators_only": "indicators_only", "high_risk": "high_risk",
            "unsupported": "unsupported"}


class MultimodalEngine:
    def analyze(self, data: bytes, filename: str = "") -> dict:
        kind = detect_kind(data)
        base = {
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }
        if kind == "image":
            result = analyze_image(data, filename)
        elif kind == "audio":
            result = analyze_audio(data, filename)
        elif kind == "video":
            result = analyze_video(data, filename)
        elif kind == "document":
            result = analyze_document(data, filename)
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
        }


multimodal_engine = MultimodalEngine()
