"""Video analysis pipeline (Phase 3). Deterministic metadata + frame statistics.

This build has NO neural detectors and NO bundled face-detection model (OpenCV 5 wheels
no longer ship Haar cascades) — results are frame/motion statistics only, reported as
PROBABILISTIC indicators with low confidence, never a deepfake verdict.
Formats depend on the OpenCV/FFmpeg codecs present; unsupported containers are reported
honestly as `unsupported`.
"""
from __future__ import annotations


def analyze_video(path: str, filename: str = "") -> dict:
    """Analyze a video file on disk (path-based: OpenCV reads the file directly,
    only sampled frames are held in memory). No extra temp copy is made."""
    result: dict = {"kind": "video", "filename": filename, "status": "unsupported", "findings": []}

    tmp_path = path

    try:
        import cv2
        import numpy as np

        cap = cv2.VideoCapture(tmp_path)
        if not cap.isOpened():
            result["error"] = "no OpenCV decoder available for this container/codec"
            result["limitations"] = ["This build analyzes only containers OpenCV can decode."]
            return result

        fps = cap.get(cv2.CAP_PROP_FPS) or 0
        frames_total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        result["status"] = "analyzed"
        result["metadata"] = {
            "fps": round(fps, 2),
            "frame_count": frames_total,
            "width": width,
            "height": height,
            "duration_seconds": round(frames_total / fps, 2) if fps else None,
        }

        # sample up to 120 frames evenly
        sample_n = 120
        step = max(1, frames_total // sample_n) if frames_total else 1
        sharpnesses, diffs = [], []
        prev_gray = None
        frames_seen = 0
        while frames_seen < sample_n:
            ok = cap.grab()
            if not ok:
                break
            ok, frame = cap.retrieve()
            if not ok:
                break
            frames_seen += 1
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            sharpnesses.append(float(cv2.Laplacian(gray, cv2.CV_64F).var()))
            if prev_gray is not None:
                diffs.append(float(np.mean(cv2.absdiff(gray, prev_gray))))
            prev_gray = gray
        cap.release()

        mean_diff = float(np.mean(diffs)) if diffs else 0.0
        result["stats"] = {
            "frames_sampled": frames_seen,
            "mean_sharpness": round(float(np.mean(sharpnesses)), 1) if sharpnesses else 0.0,
            "mean_interframe_difference": round(mean_diff, 2),
            "static_scene": bool(frames_seen > 10 and mean_diff < 1.0),
        }
        if result["stats"]["static_scene"]:
            result["findings"].append({
                "category": "static_scene_low_motion",
                "confidence": 0.15,
                "evidence": f"mean inter-frame difference {mean_diff:.2f} across {frames_seen} frames",
                "note": "weak indicator only; locked-off cameras also score here",
            })
        result["limitations"] = [
            "No neural deepfake detectors and no face-detection model are bundled in this build — "
            "results are frame statistics only (honest limitation).",
            "Results are probabilistic indicators, never identity verdicts (documented non-goal).",
            "Containers the bundled OpenCV cannot decode are reported unsupported, not guessed at.",
        ]
        return result
    except Exception as exc:
        result["error"] = f"video analysis failed: {type(exc).__name__}"
        return result
