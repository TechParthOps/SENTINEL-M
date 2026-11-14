# Development Report - Phase 3: AI & Multimodal Defense

**Date:** 2026-11-14 · **Milestone:** Phase 3 · **Status:** complete & verified (within documented honest scope)

## What was implemented

1. **AI & LLM security engine** (`backend/app/aisec/`):
   - Deterministic detectors with per-finding confidence: direct prompt injection, indirect
     injection (context-aware - instructions embedded in document/web/email content), jailbreak /
     system-prompt extraction, RAG-poisoning indicators (instruction-like text + hidden unicode
     control characters in document context), data-disclosure (API-key/token/private-key/
     credential-pair formats), agent tool-override instructions, phishing/BEC text markers
     (urgency, authority impersonation, credential/payment lures, URL indicators: shorteners,
     punycode, IP literals, non-http schemes).
   - Findings reference OWASP LLM (LLM01/LLM06) and MITRE ATLAS techniques; risk score is a
     weighted maximum with a multi-category bonus; verdicts: clean / indicators_only / high_risk.
   - API `/aisec/analyze-text` (analyst+, audit-recorded), `/aisec/analyses` (+ detail). The
     analyzed text is NOT stored - only the record (hash + result) is, matching ADR-011.
2. **Multimodal engine** (`backend/app/multimodal/`): kind-routed in-memory analysis, bytes never
   retained:
   - **image**: metadata/EXIF (incl. generative-AI tool strings: DALL·E/Midjourney/SD/Firefly/…),
     QR-code decode (OpenCV, with upscaling fallback for small/synthetic QRs) + payload threat
     analysis (shortener/IP-literal/punycode hosts, credential-lure URLs, non-web schemes),
     single-probe recompression difference ("ELA-lite", probabilistic).
   - **audio**: WAV/PCM parse + statistics (silence ratio, dynamics, clipping, spectral flatness)
     with LOW-confidence synthetic-speech indicators; MP3/OGG/FLAC reported `unsupported`, never
     guessed.
   - **video**: any OpenCV-decodable container; metadata + frame statistics (sharpness,
     inter-frame difference). No neural detectors and no bundled face model (OpenCV 5 wheels ship
     no cascades) - explicitly documented limitation; results are probabilistic indicators only.
   - **document**: PDF structural scan (/JavaScript, /OpenAction, /Launch, /EmbeddedFile, AcroForm
     + JS), OOXML zip inspection (vbaProject.bin, external links, OLE parts, binary parts).
   - API `/media/analyze` (analyst+, JSON base64, 20 MB cap, audit-recorded), `/media/analyses`.
3. **Frontend**: AI Security page (text analyzer + findings with confidences + stored records),
   Multimodal Forensics page (media submit + result rendering incl. limitations box), Malware
   page restored to its own `/malware` route with corrected title.

## Why

Phase 3 delivers the AI/multimodal threat surface with an honesty contract (ADR-008): every
detector states its method and limitations, no capability is claimed beyond what runs, and
unsupported formats are labeled `unsupported` instead of guessed.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest (adds test_aisec.py ×8, test_multimodal.py ×10) | **91/91 passed** |
| `frontend`: vitest | **7/7 passed**; production build clean |
| Live HTTP smoke (real uvicorn): email-context analysis -> high_risk (phishing + injection + tool_override); QR PNG -> 2 QR findings; health registry | passed |

## Blocked capabilities (exact dependencies)

| Capability | Blocker | Next action |
|---|---|---|
| OCR text extraction | no tesseract binary in this build | install tesseract + wire pytesseract, or bundle a Rust/python OCR |
| Neural deepfake / synthetic-speech detection | no ML runtime (torch/onnxruntime) or models bundled | optional ONNX-runtime integration with local models; document model provenance |
| MP3/OGG/FLAC audio analysis | no decoders bundled | bundle ffmpeg or an audio-decode wheel |
| Face-region video statistics | OpenCV 5 wheels ship no Haar cascades | bundle cascade/ONNX model file |

## Remaining work (next)

**Phase 4 - Autonomous investigation:** agent orchestrator, specialist agents, structured tool
schemas with permission boundaries, evidence chain-of-custody, threat-hunting queries.
