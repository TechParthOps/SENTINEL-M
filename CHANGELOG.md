# Changelog

All notable development changes. Format loosely follows Keep a Changelog; versions are phase-gates.

## [0.1.0] — Phase 1: Core Platform — 2026-11-13

### Added
- Phase 0 research library (`research/`): standards adoption (ATT&CK v20, OCSF 1.5.0, OWASP LLM
  2025/2026, NIST CSF 2.0, SP 800-61r3, AI RMF), technology comparison, 10 ADRs, coverage matrix,
  component selection, source register.
- Backend core (FastAPI + SQLAlchemy/SQLite WAL):
  - JWT auth (HS256, in-repo stdlib implementation), PBKDF2 password hashing, RBAC roles.
  - Asset inventory API (manual + telemetry auto-registration with honest source flags).
  - Event ingestion gateway (batch 1–1000, authenticated, rate-limited) + OCSF-aligned normalization
    pipeline with adapters (auth, process, network, dns, file, http; unknown types preserved as
    `generic`).
  - Deterministic detection rule engine (9 Phase-1 JSON rules across AUTH/NET/HOST/FILE/WEB with
    ATT&CK mappings, distinct-field thresholds, signature dedup + cooldown).
  - Alert management with analyst workflow (analyst+ enforced).
  - Correlation engine (entity grouping + attack-chain escalation) producing incidents with
    evidence references, ATT&CK mappings and timelines.
  - Hash-chained append-only audit log; module health registry; overview statistics API.
  - Async event bus + authenticated WebSocket streaming.
- Frontend (React 18 + TS + Vite + Tailwind v4 + Zustand + Recharts):
  - Login (real JWT), role-aware shell with full 22-item navigation; unbuilt areas render honest
    "Planned — Phase N" panels (ADR-010).
  - Overview dashboard (live metrics + charts), Live Operations (WebSocket + REST feed),
    Threat Detection (alerts + workflow), Incidents list + evidence detail, Assets, Detection
    Rules, System Health + audit view, Capabilities matrix (live coverage data), Settings.
- Docs: `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/REPORTS/phase1_report.md`, root README/SECURITY.
- Verification scripts: `scripts/smoke_test.ps1` (live attack sequence), `scripts/e2e_frontend.ps1`
  (API + SPA through the dev proxy).

### Verification
- Backend pytest: **39/39 passed**.
- Frontend vitest: **7/7 passed**; production build clean (0 TS errors).
- Live-suite: 53-event attack sequence → 5 alerts across 5 rules, escalated chain incident
  (sev 6, 3 ATT&CK techniques) with 3 evidence-linked alerts; audit hash chain valid;
  unauthorized requests rejected 401; viewer role denied alert mutations 403.

### Security
- Rate limiting on auth + ingestion; strict Pydantic validation at every boundary; audit records
  for all state-changing calls; seeded sample assets flagged `sample` in UI (ADR-008).
