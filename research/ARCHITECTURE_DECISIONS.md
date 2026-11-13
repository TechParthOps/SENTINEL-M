# SENTINEL-M — Architecture Decision Records

Format: lightweight ADR. Status: Accepted | Superseded by ADR-xxx.

---

## ADR-001 — Modular monolith first, workers later
**Status:** Accepted (2026-11-12)
**Context:** Single workstation + small-team product; microservices would add ops cost with no scale need yet.
**Decision:** One FastAPI process with internally modular packages (`ingestion/`, `detection/`,
`correlation/`, …). Long/heavy work (model inference, sandboxing) moves to worker processes in
later phases behind the same service interfaces.
**Consequences:** Simple deploy (one command). Module boundaries enforced by import rules and tests.

## ADR-002 — Password hashing: PBKDF2-HMAC-SHA256 (stdlib)
**Status:** Accepted (2026-11-12)
**Context:** Need strong, dependency-light hashing that builds reliably on Windows/Py3.11.
**Decision:** `hashlib.pbkdf2_hmac("sha256", pw, salt, 600_000)` with 16-byte random salt,
constant-time comparison. Parameters stored with the hash (`pbkdf2_sha256$600000$salt$hash`)
so they can be upgraded without breaking old hashes.
**Consequences:** No native wheels. Argon2 via passlib may supersede at enterprise hardening
(re-encrypt transparently on next login).

## ADR-003 — JWT (HS256) implemented in-repo on stdlib
**Status:** Accepted (2026-11-12)
**Context:** Auth needed for API + WebSocket; avoid dependency sprawl at Phase 1.
**Decision:** Minimal HS256 sign/verify module (`core/jwthttp.py` ≤ 60 lines, stdlib `hmac`,
`base64url`, constant-time compare), short-lived tokens (default 8h), `iat`/`exp`/`sub`/`role` claims.
**Consequences:** Auditable code, no supply-chain surface. Swap to PyJWT/OIDC behind the same
`core/security.py` facade when enterprise SSO lands (Phase 7). Key from config/env — never in code.

## ADR-004 — Canonical event model: OCSF-aligned subset
**Status:** Accepted (2026-11-12)
**Context:** Multiple source formats (Sysmon XML, Zeek logs, Suricata EVE, generic JSON) must land
in one schema; full OCSF validation is heavy for Phase 1.
**Decision:** Internal `NormalizedEvent` with OCSF-style fields: `class_uid`, `activity_id`,
`severity_id` (0–6), `time`, `metadata(product,version,uid)`, `observables[]`, `actor`,
`src_endpoint`, `dst_endpoint`, `connection_info`, `file`, `process`, `http_request`,
`raw_ref`. Ingestion adapters map source → canonical; detection/correlation only ever see canonical.
**Consequences:** Adapters are the only place vendor knowledge lives. Full ocsf-schema validation
can be layered later without touching engines.

## ADR-005 — Detection: deterministic JSON rule engine, no LLM in the hot path
**Status:** Accepted (2026-11-12)
**Context:** Spec demands explainability, no silent rule mutation, and continued operation when
the LLM is down.
**Decision:** Rules are declarative JSON (`type: threshold | pattern | sequence`), versioned,
load-verified at startup, evaluated in-process per event batch. ML/LLM verdicts may *annotate*
alerts with confidence but never create/modify rules or alerts autonomously (Part 15 constraint).
**Consequences:** Every detection is reproducible in tests; Sigma import (Phase 2) compiles into
these rule objects.

## ADR-006 — Correlation: time-window entity grouping with explicit chain rules
**Status:** Accepted (2026-11-12)
**Context:** Alerts must become incidents with a narrative, not noise.
**Decision:** Two mechanisms: (a) entity-time grouping (same asset/source within window → one
incident), (b) chain rules (ordered technique sequences e.g. suspicious-execution →
credential-access → lateral-movement → C2 on same host within N minutes → "suspected intrusion
chain" incident with elevated severity). Evidence references are stored on the incident.
**Consequences:** Deterministic, inspectable; APT narrative quality improves with more chain
rules over time.

## ADR-007 — Real-time layer: in-process asyncio event bus + WebSocket fanout
**Status:** Accepted (2026-11-12)
**Context:** 3D office (Phase 6) and Live Operations need sub-second push of events/alerts/
incidents/agent-state; Redis is optional, not required.
**Decision:** `EventBus` (asyncio, per-topic subscriber sets) inside the API process. WS endpoint
subscribes with topic filters + auth. Durable state stays in SQLite; bus is lossy-by-design for
disconnected clients (they catch up via REST since-query).
**Consequences:** Zero infra to run locally. If a multi-node deployment appears (Phase 7), the bus
interface is replaced by Redis pub/sub without touching producers.

## ADR-008 — Honesty constraints baked into architecture
**Status:** Accepted (2026-11-12) — **non-negotiable**
**Decision:**
1. Every UI metric resolves to a REST/WS field with a real data path, or renders an explicit
   `simulation` / `planned` badge.
2. Response actions transition to `executed` **only** on enforcement-adapter confirmation; failures
   propagate to UI (Phase 5).
3. LLM findings require rule/evidence corroboration to escalate severity (Phase 3+).
**Consequences:** Slightly slower "demo" feel, dramatically higher trustworthiness.

## ADR-009 — SQLite (WAL) for Phase 1, PostgreSQL for enterprise
**Status:** Accepted (2026-11-12)
**Decision:** SQLAlchemy 2.x ORM with a single connection-url config. SQLite in WAL mode with
indexes on (time), (class_uid), (host), (source_ip). Postgres target documented in deployment docs.
**Consequences:** Zero-install dev; migration path is a config change + migration scripts.

## ADR-010 — Frontend honest-status navigation
**Status:** Accepted (2026-11-12)
**Context:** 22 nav items in the product spec; most engines arrive in Phases 2–6.
**Decision:** All 22 items exist in the navigation from day one, but unbuilt areas render an
explicit "Planned — arrives in Phase N" panel; implemented areas show live data. A
`/capabilities` page renders the coverage matrix.
**Consequences:** No fake dashboards, ever; users see the roadmap in-product.
