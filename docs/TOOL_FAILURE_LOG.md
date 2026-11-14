# SENTINEL-M - Tool Failure Log

**Updated:** 2026-11-14

| # | Task attempted | Error | Resolution |
|---|---|---|---|
| 1 | `read docs/REPORTS/phase1_report.md` (parallel with ARCHITECTURE.md) | none - completed | n/a |
| 2 | edit `main.py` router registration (first attempt) | oldString not found (router block ordering differed from memory) | re-read the actual file section and applied the edit with exact text |
| 3 | PowerShell 5 `pytesseract.get_tesseract_version()` | tesseract binary missing (stderr traceback) | recorded as an honest BLOCKED capability; no OCR claims made; multimodal image pipeline states the limitation in its results |
| 4 | QR decode in tests (OpenCV 5.0) | `QRCodeDetector.detectAndDecode` returned '' on small synthetic QR images | analyzer upscales with INTER_NEAREST + quiet-zone fallback; verified round-trip decode |
| 5 | `cv2.data.haarcascades` face detection | OpenCV 5.0 wheel ships no cascade XML files (`Can't open file … haarcascade_frontalface_default.xml`) | removed face-region heuristics; video pipeline now reports statistics only with an explicit "no face model bundled" limitation |
| 6 | Live smoke login (server on :8123) | `invalid credentials` - dev DB seeded with a different/random password | used the documented smoke-test seed password (`SENTINEL_SEED_ADMIN_PASSWORD=Smoke!Admin1` per `scripts/smoke_test.ps1`) |
| 7 | Live smoke media call (first attempt) | empty file - PowerShell wrote `_qr.png` to session cwd but read it from `backend\` | fixed absolute path; verified |
| 8 | uvvicorn bind on `127.0.0.1:8000` (office live verification) | Windows socket permission error - 8000 sits in an excluded port range | used 8942 (same range as the proven smoke port 8941); vite dev proxy retargeted via `VITE_API_TARGET`/`VITE_WS_TARGET` |
| 9 | `browser.screenshot` of the 3D office | visible desktop window required - unavailable in this shell environment | verified the 3D view via DOM/state assertions instead (canvas mounted, WS connected, room counts match REST data); pixel capture recorded as honestly blocked in the Phase 6 report |
| 10 | `python -m pytest` run from repo root for final verification | collection cwd mismatch: tests only isolated via `backend/` conftest; root runs hung near 75% | re-ran from `backend/` (documented in the session log); result **110/110 passed** |
| 11 | `test_coverage_endpoint_matches_matrix` after Phase-6 coverage update | test hard-coded `phases[6] == "planned"` — stale once Phase 6 shipped | updated the test to assert implemented + the deliberately-declined capability still `planned`; suite green |
| 12 | Pixel capture + 3D pointer picking of the upgraded office (realistic environment) | browser tab is hidden in this environment: `requestAnimationFrame` never fires (verified with a probe), so the WebGL canvas never paints a frame and R3F pointer raycasts never run; `browser.screenshot` needs a visible desktop window | environment limitation recorded honestly in phase6_report/CHANGELOG/FINAL_REPORT; the upgrade is validated by tsc/build gates, a clean mount with zero console errors on a live server, and the real-data layer; the earlier office build was verified end-to-end in this same harness when frames flowed |
| 13 | Large single `write` calls on `OfficeScene.tsx` (upgrade) | tool call repeatedly interrupted mid-payload — the file stayed at its old 193-line content | switched to a sequence of smaller targeted `edit` operations; final file verified by tsc/vitest/build |

Rule applied per master prompt §2.2: each failure was inspected once, corrected, and moved past -
no repeated identical attempts. Nothing was fabricated to fill a failed tool result.
