"""Audio analysis pipeline (Phase 3). WAV (PCM) only in this build — honest limits.

Heuristic synthetic-speech indicators: spectral flatness / dynamics statistics on the
whole file. These are PROBABILISTIC and low-confidence; they are never an identity or
"deepfake" verdict. MP3/OGG/Opus decode requires decoders that are not bundled — such
files are reported as `unsupported` rather than guessed at.
"""
from __future__ import annotations


def analyze_audio(path: str, filename: str = "") -> dict:
    """Analyze a WAV/PCM file on disk. Only a bounded window (5 minutes) of
    samples is decoded into memory."""
    result: dict = {"kind": "audio", "filename": filename, "status": "unsupported", "findings": []}

    # quick container sniff
    with open(path, "rb") as probe:
        head = probe.read(16)
    if head.startswith(b"ID3") or head[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"):
        result["error"] = "MP3 container detected; MP3 decoding is not bundled (WAV PCM only)"
        result["limitations"] = ["Provide WAV (PCM) for analysis in this build."]
        return result
    if head.startswith(b"OggS"):
        result["error"] = "OGG container detected; OGG decoding is not bundled (WAV PCM only)"
        result["limitations"] = ["Provide WAV (PCM) for analysis in this build."]
        return result
    if not head.startswith(b"RIFF") or head[8:12] != b"WAVE":
        result["error"] = "not a RIFF/WAVE stream"
        return result

    import wave

    try:
        wf = wave.open(path)
        channels, rate, duration = wf.getnchannels(), wf.getframerate(), wf.getnframes() / wf.getframerate()
        if rate == 0 or duration <= 0:
            raise ValueError("empty or zero-rate audio")
        import numpy as np

        raw = wf.readframes(min(wf.getnframes(), rate * 300))  # cap at 5 minutes
        width = wf.getsampwidth()
        wf.close()
    except Exception as exc:
        result["error"] = f"WAV parse failed: {type(exc).__name__}"
        return result

    dtype = {1: np.int8, 2: np.int16, 4: np.int32}.get(width)
    if dtype is None:
        result["error"] = f"unsupported sample width {width} bytes (PCM 8/16/32 supported)"
        return result
    samples = np.frombuffer(raw, dtype=dtype).astype(np.float64)
    if channels > 1:
        samples = samples[::channels]  # one channel; sufficient for statistics

    result["status"] = "analyzed"
    result["metadata"] = {
        "channels": channels,
        "sample_rate": rate,
        "duration_seconds": round(duration, 2),
        "sample_width_bytes": width,
    }

    abs_amp = np.abs(samples) / (2 ** (8 * width - 1))
    frame = max(rate // 10, 1)
    n_frames = len(samples) // frame
    findings = []
    stats = {}
    if n_frames > 10:
        # per-frame RMS over the sampled region
        frames = samples[:n_frames * frame].reshape(n_frames, frame)
        frame_rms = np.sqrt(np.mean((frames / (2 ** (8 * width - 1))) ** 2, axis=1))
        silence_ratio = float((frame_rms < 1e-4).mean())
        dyn_range = float(frame_rms.max() - frame_rms.min())
        clipping = float((abs_amp > 0.99).mean())
        flatness = _spectral_flatness(samples, rate)
        stats.update({
            "silence_ratio": round(silence_ratio, 3),
            "dynamic_range": round(dyn_range, 4),
            "clipping_ratio": round(clipping, 5),
            "spectral_flatness": round(flatness, 4),
        })
        # Heuristic synthetic-speech indicators (LOW confidence, probabilistic):
        if 0 <= silence_ratio <= 0.01 and duration > 10:
            findings.append({
                "category": "no_natural_pauses",
                "confidence": 0.35,
                "evidence": f"silence ratio {silence_ratio:.3f} over {duration:.0f}s — natural speech pauses absent",
                "note": "weak indicator; scripted audio also scores here",
            })
        if dyn_range > 0 and (flatness < 0.001 and clipping > 0.2):
            findings.append({
                "category": "unnatural_dynamics",
                "confidence": 0.3,
                "evidence": f"spectral flatness {flatness:.5f} with clipping ratio {clipping:.3f}",
                "note": "weak indicator; loud mastered audio scores here",
            })
    result["stats"] = stats
    result["findings"] = findings
    result["limitations"] = [
        "WAV (PCM) only in this build — MP3/OGG/Opus/FLAC are reported unsupported, not analyzed.",
        "Indicators are statistical and low-confidence; never a voice-identity or deepfake verdict.",
        "No ASR transcription is bundled — transcript-level checks (e.g. liveness prompts) not available.",
    ]
    return result


def _spectral_flatness(samples, rate: int) -> float:
    import numpy as np

    seg = samples[: min(len(samples), rate * 30)]
    if len(seg) < 512:
        return 0.0
    spectrum = np.abs(np.fft.rfft(seg))
    spectrum = spectrum[spectrum > 1e-9]
    if spectrum.size == 0:
        return 0.0
    log_mean = np.mean(np.log(spectrum))
    mean = np.mean(spectrum)
    if mean <= 0:
        return 0.0
    return float(np.exp(log_mean) / mean)
