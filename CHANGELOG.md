# Changelog

All notable development changes. Format loosely follows Keep a Changelog; versions are phase-gates.

## [0.1.0] — Phase 1: Core Platform — 2026-11-12

### Added
- Phase 0 research library (`research/`): standards adoption (ATT&CK v20, OCSF 1.5.0, OWASP LLM
  2025/2026, NIST CSF 2.0, SP 800-61r3, AI RMF), technology comparison, 10 ADRs, coverage matrix,
  component selection, source register.
- Backend core (FastAPI + SQLAlchemy/SQLite WAL):
  - JWT auth (HS256, in-repo stdlib implementation), PBKDF2 password hashing, RBAC roles.
  - Asset inventory API.
  - Event ingestion gateway (batch, authenticated, rate-limited) + OCSF-aligned normalization
    pipeline with source adapters (generic JSON, syslog-style auth, process, network, dns, file,
    http).
  - Deterministic detection rule engine (JSON rules, 8 Phase-1 rules across AUTH/NET/HOST/FILE/WEB).
  - Alert management, correlation engine (entity-time grouping + attack-chain rules) producing
    incidents with evidence references and ATT&CK mappings.
  - Audit log (hash-chained, append-only).
  - Async event bus + authenticated WebSocket streaming (events/alerts/incidents/health topics).
  - System health registry + health API.
  - Overview statistics API.
- Frontend (React 18 + TS + Vite + Tailwind + Zustand + Recharts):
  - Login (real JWT), role-aware shell with full 22-item navigation; unbuilt areas render honest
    "Planned — Phase N" panels (ADR-010).
  - Overview dashboard (live metrics from API), Live Operations (WebSocket event feed),
    Incidents list + detail (evidence, ATT&CK mapping, timeline), Assets, Detection Rules,
    System Health, Capabilities matrix page.
- Backend test suite (pytest): auth, ingestion/normalization, detection rules, correlation,
  audit chain, health, RBAC.
- Frontend: Vite build verification + smoke render test.

### Security
- Rate limiting on auth + ingestion; strict Pydantic validation; audit records for all
  state-changing calls.
