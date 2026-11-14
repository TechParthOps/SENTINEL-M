# SENTINEL-M Architecture - Phase 1

> This document describes **what is implemented and running today**. Planned engines are
> listed in `research/THREAT_COVERAGE_MATRIX.md` and the in-app Capabilities page.

## 1. System shape

One FastAPI process ("modular monolith", ADR-001) serving:

- **REST API** under `/api/v1` (OpenAPI docs auto-served at `/docs`).
- **WebSocket** live stream at `/ws` (ADR-007).
- SQLite database in WAL mode (ADR-009, `backend/data/sentinel.db`).
- In-process async event bus with authenticated WS fanout.

```
                    ┌──────────────────────── SENTINEL-M backend (FastAPI) ───────────────────────┐
 collectors ──HTTP-> │ Ingestion Gateway -> Normalizer -> Event store (SQLite)                        │
  (agents/tests)    │        │                    │                                                │
                    │        ▼                    ▼                                                │
                    │ Detection Engine      Correlation Engine   -> Incidents                       │
                    │ (JSON rules,          (entity grouping +                                     │
                    │  threshold/pattern)    attack-chain escalation)                              │
                    │        │                    │                                                │
                    │        └────── EventBus (topics: events/alerts/incidents/assets/health) ────┐ │
                    │                                                          │                  │ │
                    │ Audit log (hash-chained)        Health registry           ▼                  │ │
                    └─────────────────────────────────────────────────────────────────────────────┼─┘
                                                                              WebSocket fanout     │
  Frontend (React + Vite, port 5173) ──fetch REST───▶ /api/v1  ◀────────── WS /ws ◀──────────────┘
```

## 2. Module inventory (all report health at `/api/v1/health`)

| Module | Package | Responsibility |
|---|---|---|
| Auth / RBAC | `app/core/security.py` | JWT (HS256), PBKDF2 hashing, role dependencies |
| Config | `app/core/config.py` | `SENTINEL_*` env settings (pydantic-settings) |
| Database | `app/core/database.py` | SQLAlchemy engine/session, WAL pragmas |
| Event bus | `app/core/bus.py` | Async pub/sub, thread-safe publish |
| Health registry | `app/core/health.py` | Per-module liveness checks |
| Audit | `app/core/audit.py` | Append-only, SHA-256 hash-chained log |
| MFA | `app/core/mfa.py` | TOTP (RFC 6238, stdlib-only) + single-use recovery codes; step-up token scope enforced in `app/core/security.py` - Phase 7 |
| Rate limit | `app/core/ratelimit.py` | In-memory per-identity fixed window |
| Ingestion | `app/ingestion/` | Gateway + OCSF-aligned normalizer + adapters |
| Detection | `app/detection/` | Rule model + engine, JSON rules in `detection-rules/` |
| Correlation | `app/correlation/engine.py` | Alerts -> incidents, chain escalation |
| Identity | `app/identity/engine.py` | Cross-session auth correlation (geo-change annotation) - Phase 2 |
| Intelligence | `app/intelligence/` | STIX 2.1 import, indicator aging, event IOC enrichment - Phase 2 |
| Malware | `app/malware/` | Static file analysis (hashes/entropy/PE/strings/archives/macros) - Phase 2 |
| AI security | `app/aisec/` | LLM-facing text analysis: injection, jailbreak, RAG poisoning, disclosure, phishing - Phase 3 |
| Multimodal | `app/multimodal/` | Image/QR, WAV audio, video, PDF/OOXML pipelines (bytes never retained) - Phase 3 |
| Agents | `app/agents/` | Orchestrator + 5 deterministic read-only specialists, SHA-256 evidence chain, time budget - Phase 4 |
| Hunt | `app/api/hunt.py` | Read-only IOC/entity/class sweeps over retained events + alerts - Phase 4 |
| Response | `app/response/` | Allowlisted actions, L0/L1/L2 autonomy, approval, execution, verification, rollback; `SENTINEL_RESPONSE_ENABLED` emergency stop - Phase 5 |
| Deception | `app/deception/` | Honeypot listeners (loopback default), decoy credentials, canary tokens, DECEPTION-HP-001 alerts - Phase 5 |
| 3D office | `frontend/src/components/OfficeScene.tsx`, `frontend/src/store/office.ts` | R3F digital twin: room metrics from REST, markers from confirmed WS frames, replay of real alerts, 2D fallback - Phase 6 |
| API | `app/api/` | auth, events, assets, alerts, incidents, identity, intelligence, malware, aisec, media, agents, hunt, response, deception, rules, stats, system, ws |
| Services | `app/services/seed.py` | First-admin + labeled sample inventory |

## 3. Data flow: one event's journey

1. **POST** `/api/v1/events/ingest` with `{source, events:[{type, payload}]}` (JWT auth, rate-limited, validated).
2. **Normalize**: type -> OCSF-aligned class (auth->authentication, process->process_activity,
   network->network_activity, dns->dns_activity, file->file_activity, http->web_resource_access_activity,
   unknown -> `generic`, never dropped). Observables extracted (ipv4, domain, url).
3. **Persist** `events` row; auto-register the source host in `assets` (flagged `auto_registered`).
4. **Detect**: every rule is evaluated against the event view (raw payload + normalized fields).
   Threshold rules use sliding windows + distinct-field counting; pattern rules require ALL
   regexes to match, with signature dedup + cooldown. Fires create an `alerts` row with
   `evidence_event_ids` and ATT&CK mappings.
5. **Correlate**: alert groups into an `incidents` row by entity (host/IP) across open incidents;
   ≥2 distinct techniques = `attack_chain` -> severity escalated, category `potential_intrusion`,
   human-readable evidence-linked narrative.
6. **Broadcast**: event/alert/incident published on the bus -> WebSocket clients.
7. **Audit**: ingestion and every state-changing call recorded in the hash-chained log.

## 4. Security controls (implemented)

- All API/WS access requires a valid JWT; tokens carry `sub`, `role`, `exp`.
- Roles: `viewer` < `analyst` < `admin`, enforced per endpoint (e.g., alert workflow = analyst+,
  audit log = admin only).
- Passwords: PBKDF2-HMAC-SHA256 (600k iterations), policy ≥10 chars with letter+digit.
- Self-registration (policy-gated, audit-recorded) can only create viewer/analyst accounts -
  never admin. Disable with `SENTINEL_ALLOW_SELF_REGISTRATION=false`.
- Rate limits on login and ingestion (in-memory; documented as not a replacement for perimeter controls).
- Audit log: append-only, SHA-256 hash chain, verifiable at `/api/v1/audit`.
- Secrets: only in env (`SENTINEL_SECRET_KEY` required; startup warns if insecure).

## 5. Honesty constraints (ADR-008)

- Sample inventory is flagged `sample=true` and labeled as such in the UI.
- "Planned" capabilities render an explicit panel and a `P#` nav badge - never fake data.
- The coverage endpoint exposes runtime truth (`rules_loaded`, phase status).

## 6. Local-first, offline-capable

No external service is required: SQLite lives on disk, LLM/AI features are planned behind an
abstraction layer (Phase 3+) that must degrade gracefully. Nothing in Phase 1 phones home.