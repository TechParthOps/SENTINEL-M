# SENTINEL-M - Remaining Work

**Updated:** 2026-11-14 · Source of truth for what is left (status legend mirrors the coverage matrix)

## Completed (this session)

| Phase | Outcome |
|---|---|
| 4 - Autonomous investigation | ✅ orchestrator + 5 read-only specialists, SHA-256 evidence chain, hunt API (`docs/REPORTS/phase4_report.md`) |
| 5 - Response & deception | ✅ allowlist response engine (approval/verify/rollback + emergency stop), loopback honeypots (`docs/REPORTS/phase5_report.md`) |
| 6 - 3D virtual office | ✅ R3F office live-synced to real REST/WS data, replay, 2D fallback (`docs/REPORTS/phase6_report.md`) |
| 7 - Enterprise readiness (partial) | ✅ MFA/TOTP, local installer, backup tool, SBOM, performance smoke (`docs/REPORTS/phase7_report.md`) |

## Phase 7 — remaining items

| Capability | Status | Dependency / next action |
|---|---|---|
| Packaged distribution + automated updates | 📋 planned | PyInstaller/Electron packaging, signed update channel — not in this build |
| SSO / SAML / LDAP federation | 🚫 blocked | external identity provider |
| Ticketing / chatops response integrations | 🚫 blocked | external workflow provider |
| WebAuthn / FIDO2 hardware keys (MFA is TOTP-only today) | 📋 planned | authenticator-attestation flow + attestation verification |

> UI placeholders that used to appear here (Digital Forensics, Integrations, Reports) are
> now real pages backed by live data — see `docs/IMPLEMENTATION_MATRIX.md`. Raw-JSON
> displays on System Health and Settings were replaced with readable layouts.

## Blocked (requires unavailable external components - do NOT fake)

| Capability | Exact dependency |
|---|---|
| OCR text extraction | tesseract binary (not installed in this build) |
| Neural deepfake / synthetic-speech detectors | ML runtime (torch/onnxruntime) + local model files |
| MP3/OGG/FLAC audio decode | ffmpeg or an audio-decode wheel |
| Face-region video statistics | bundled cascade/ONNX face model (OpenCV 5 ships none) |
| MISP/OpenCTI/TAXII live feed clients | reachable external instance + credentials (Phase 2 uses local STIX files offline) |
| YARA scanning + sandboxed dynamic malware analysis | yara-python + isolated VM/sandbox target |

## Commit policy note

Phases 2-7 are complete, tested and documented but uncommitted (master prompt forbids commits
without explicit user authorization).
