# Development Report — Phase 1: Core Platform

**Date:** 2026-11-13 · **Milestone:** Phase 1 (per Part 19 methodology) · **Status:** complete & verified

## What was implemented

1. **Research & architecture (Phase 0):** seven research documents under `research/` — standards
   adoption (MITRE ATT&CK v20, OCSF 1.5.0, OWASP LLM 2025/2026, NIST CSF 2.0, SP 800-61r3,
   AI RMF), technology comparison, 10 ADRs, threat coverage matrix, component selection,
   source register with verification dates.
2. **Backend core (FastAPI + SQLAlchemy + SQLite WAL):**
   - Authentication: JWT (HS256, stdlib implementation), PBKDF2-SHA256 password hashing, RBAC
     (viewer/analyst/admin), password policy enforcement, self-registration policy (non-admin only).
   - Event ingestion gateway: authenticated, rate-limited, batch 1–1000, audit-recorded.
   - Normalization: OCSF-aligned canonical model; adapters for auth/process/network/dns/file/http;
     unknown types preserved as `generic`; observable extraction (ipv4/domain/url with message-domain
     scanning).
   - Asset inventory: manual registration + telemetry auto-registration with honest source flags
     (`auto_registered`, `sample`).
   - Detection engine: declarative JSON rules (threshold with distinct-field counting, pattern with
     signature dedup and cooldown), 9 Phase-1 rules mapped to ATT&CK (T1110, T1110.003, T1087.001,
     T1046, T1059.001, T1053.005, T1071.004, T1486, T1190).
   - Correlation engine: entity-time grouping into incidents, attack-chain detection
     (≥2 distinct techniques), severity escalation with explanation, evidence-linked timelines.
   - Alert + incident workflow APIs with role enforcement.
   - Hash-chained append-only audit log; module health registry; overview statistics API.
   - Async event bus + authenticated WebSocket stream (ADR-007).
3. **Frontend (React 18 + TS + Vite + Tailwind v4 + Zustand + Recharts):**
   - Real JWT login; full 22-item navigation with honest "Planned — Phase N" panels (ADR-010).
   - Overview dashboard (live metrics, real charts from API), Live Operations (REST backfill +
     WebSocket stream), Threat Detection (alerts + analyst workflow), Incident detail with
     evidence timelines and analyst notes, Assets, Detection Rules, System Health + audit,
     Capabilities matrix (from backend coverage data), Settings.

## Why

Phase 1 is the foundation every later phase plugs into: a working, tested, honest data pipeline
(events → normalized → detection → alerts → incidents → live UI) that later engines extend, plus
the security substrate (auth, RBAC, audit, health) that the autonomous features must respect.

## Files created (principal)

- Backend: 33 modules under `backend/app/` (core, models, ingestion, detection, correlation,
  api, services), 9 rule files under `detection-rules/`, tests under `backend/tests/`.
- Frontend: 21 files under `frontend/src/` (pages, components, stores, lib).
- Docs: `research/` (7 files), `docs/ARCHITECTURE.md`, `docs/API.md`, this report.
- Scripts: `scripts/smoke_test.ps1`, `scripts/e2e_frontend.ps1`.
- Repo metadata: `README.md`, `SECURITY.md`, `CHANGELOG.md`, `.gitignore`.

## Files preserved

`backend/app/main.py`, `backend/tests/*`, `requirements.txt`, `.env.example` (interrupted-session
scaffold) — all preserved and completed against their contracts. Three stale overlapping files
from the interrupted session (`app/models/entities.py`, `app/api/deps.py`, `app/core/rate_limit.py`)
were removed as conflicting duplicates of the new implementation.

## Architectural changes during the phase

- Chose PBKDF2 + stdlib JWT over passlib/PyJWT for dependency minimalism (ADR-002/003).
- Normalizer exposes a combined event "view" (raw payload + normalized fields) to rules so vendor
  field names live only in adapters (ADR-004).
- Correlation uses DB-backed open-incident lookup rather than in-memory-only state (survives
  process restarts within the same DB).
- Test isolation fix: engine state reset now also clears alert/incident DB rows (prevents
  cross-test alert-count contamination).

## New dependencies

Backend: fastapi, uvicorn[standard], SQLAlchemy, pydantic, pydantic-settings, httpx, pytest
(no native wheels; all already present on target).
Frontend: react, react-dom, react-router-dom, zustand, recharts, tailwindcss v4 (@tailwindcss/vite),
vite, typescript, vitest.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest (39 tests: auth/RBAC, ingestion/normalization, 9 detection rules, correlation, audit chain, system, WS) | **39/39 passed** |
| `frontend`: vitest (7 tests: formatters, severity mapping, RBAC ranking) | **7/7 passed** |
| Frontend production build (`tsc -b && vite build`) | **clean, 0 errors** |
| `scripts/smoke_test.ps1` (live server, 53-event attack sequence) | passed: 5 alerts across 5 rules, chain incident sev=6 with 3 ATT&CK techniques, audit chain valid, invalid token rejected |
| `scripts/e2e_frontend.ps1` (API + vite proxy + SPA) | passed: shell served, proxied login/stats/rules, deep-link fallback |

## Known issues / limitations (documented, Phase-2 targets)

1. Events ingestion and detection are synchronous in-request; high-volume sources will need the
   worker/queue split (planned with network/endpoint engines).
2. Rate limiter is in-memory (single node) — explicitly not a perimeter control.
3. Self-registration default-on is a bootstrap convenience; SECURITY.md documents disabling it.
4. No MFA yet (Phase 7); no full-packet capture (metadata only, by design).
5. WS reconnects from event history via REST only (bus is lossy for disconnected clients).

## Remaining work (next)

**Phase 2 — Traditional Cyber Defense:** network + endpoint telemetry adapters, identity &
web/API engines, malware static analysis, threat-intelligence engine with IOC aging, hunt queries.

## How to run and verify

```powershell
# backend
cd backend; python -m uvicorn app.main:app --reload
# run tests
cd backend; python -m pytest -q
# frontend
cd frontend; npm run dev          # http://localhost:5173
# full-stack verification scripts
powershell -File scripts\smoke_test.ps1
powershell -File scripts\e2e_frontend.ps1
```