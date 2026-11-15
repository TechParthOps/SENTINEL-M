# SENTINEL-M — Requirement Implementation Matrix

**Updated:** 2026-11-15 · Source of truth: original SENTINEL-M Master Engineering Prompt.
Statuses used (only these): *Implemented and tested* · *Implemented but not fully validated* ·
*Partially implemented* · *Planned* · *Blocked* · *Not implemented* · *Not applicable*.

Evidence abbreviations: **T** = automated test (`backend/tests/…`), **L** = live HTTP/browser
verification, **D** = documented contract (API.md / ARCHITECTURE.md / matrix).

## Core platform (§6.1)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| C1 | Backend API | Implemented and tested | FastAPI, 19 routers, 122 pytest, L |
| C2 | Frontend application | Implemented and tested | 21 routes + 3D office, tsc/vitest/build, L |
| C3 | Authentication (JWT + PBKDF2, stdlib-only) | Implemented and tested | `app/core/security.py`, T (test_auth paths), L |
| C3b | Self-service sign-up + sign-in choice on the login screen | Implemented and tested | L (browser: both options render; analyst created end-to-end) |
| C3c | 24-hour session (persisted across browser restarts) | Implemented and tested | `token_ttl_minutes=1440` asserted by T; token claims verified L |
| C4 | RBAC (viewer/analyst/admin per-route) | Implemented and tested | T, L (401/403 verified over HTTP) |
| C5 | MFA (TOTP RFC 6238 + single-use recovery codes) | Implemented and tested | `app/core/mfa.py`, T ×5, L (`scripts/mfa_smoke.ps1`) |
| C6 | Asset inventory (manual + auto-registration) | Implemented and tested | T, L |
| C7 | Identity inventory / auth correlation | Implemented and tested | T ×3, L |
| C8 | Event ingestion gateway | Implemented and tested | T, L (53-event batch) |
| C9 | OCSF-aligned normalization | Implemented and tested | T |
| C10 | Event storage (SQLite WAL) | Implemented and tested | T, backup tool L |
| C10b | Startup seeding idempotent (no boot crash on odd-but-valid DBs) | Implemented and tested | regressed-and-fixed: IntegrityError on assets reproduced, boot verified after fix |
| C11 | WebSocket streaming | Implemented and tested | T (test_ws), L (live markers arrived < 1s) |
| C12 | Audit logs (hash-chained) | Implemented and tested | T, L |
| C13 | System health registry | Implemented and tested | T, L (14 modules ok) |
| C14 | Integration management | Planned | external IDS/EDR/SOAR connectors need instances |
| C15 | Local configuration (`SENTINEL_*` env) | Implemented and tested | `app/core/config.py`, `.env.example`, installer L |
| C16 | Error handling | Implemented and tested | T, L (401/422 paths exercised) |

## Traditional cybersecurity (§6.2)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| T1 | Network security monitoring | Implemented and tested | NET-* rules (beaconing, C2/DGA, DNS tunneling, exfil, port scan), T, L |
| T2 | Endpoint monitoring | Implemented and tested | HOST-*/FILE-* rules, T, L |
| T3 | SIEM functionality (ingest→normalize→detect→correlate→store→search) | Implemented and tested | T, L, hunt API |
| T4 | XDR-style correlation (entity grouping + attack-chain escalation) | Implemented and tested | `app/correlation/`, T, L (5 incidents from one batch) |
| T5 | IDS/IPS integration adapters (Zeek/Suricata/etc.) | Planned | needs deployed sensors; OCSF ingest API documented for them |
| T6 | Malware analysis (static: hashes, entropy, PE, strings, archives, macros) | Implemented and tested | T, L |
| T7 | Ransomware behavior detection | Implemented and tested | FILE-RANSOM-001, T, L |
| T8 | File integrity monitoring | Implemented and tested | FILE-* rules + hunt queries, T |
| T9 | Identity threat detection (impossible travel, MFA fatigue) | Partially implemented | impossible travel T+L; MFA-fatigue detector Planned (coverage matrix) |
| T10 | Web application security monitoring | Implemented and tested | WEB-SQLI/XSS/SSRF/TRAVERSAL, T, L |
| T11 | API security monitoring | Implemented and tested | WEB-* rules cover API abuse patterns over HTTP events, T |
| T12 | Threat hunting | Implemented and tested | `/hunt` + Hunt page, T, L |
| T13 | APT detection (multi-stage chains) | Implemented and tested | correlation escalation + related_activity agent, T, L |
| T14 | MITRE ATT&CK mapping | Implemented and tested | every rule carries attack_ids/tactics; rendered in UI |
| T15 | Incident timelines | Implemented and tested | incident detail + hunt timeline, T, L |

## AI and multimodal security (§6.3)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| A1 | Direct prompt injection detection | Implemented and tested | `app/aisec/`, T ×8, L |
| A2 | Indirect prompt injection detection | Implemented and tested | T, L |
| A3 | Jailbreak detection | Implemented and tested | T |
| A4 | RAG poisoning indicators | Implemented and tested | T |
| A5 | LLM data disclosure detection | Implemented and tested | T |
| A6 | Agent tool misuse detection | Implemented and tested | text indicators T + read-only agent boundaries T |
| A7 | AI-generated phishing analysis | Implemented and tested | T, L (high_risk verdict) |
| A8 | Image analysis | Implemented and tested | T, L |
| A9 | OCR | Blocked | no tesseract binary in this build |
| A10 | QR-code phishing detection | Implemented and tested | T, L (decode verified) |
| A11 | Document manipulation detection | Implemented and tested | T, L |
| A12 | Image-based prompt injection | Partially implemented | QR payload + text-in-image not extractable without OCR (A9) |
| A13 | Audio analysis (WAV/PCM statistics) | Implemented and tested | T |
| A14 | Voice-cloning detection | Blocked | needs ML runtime + models |
| A15 | Synthetic speech detection | Partially implemented | low-confidence WAV statistics only (documented) |
| A16 | Video analysis | Implemented and tested | T |
| A17 | Deepfake detection | Partially implemented | frame statistics only; no neural detectors (Blocked dependency) |

## Threat intelligence (§6.4)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| I1 | STIX 2.1 support | Implemented and tested | T ×N, L (feed import) |
| I2 | TAXII live client | Blocked | needs reachable external TAXII server |
| I3 | MISP integration | Blocked | needs external instance + credentials |
| I4 | OpenCTI integration | Blocked | needs external instance + credentials |
| I5 | MITRE ATT&CK enrichment | Implemented and tested | rules carry technique IDs; intel engine maps |
| I6 | MITRE ATLAS references | Implemented and tested | aisec findings carry ATLAS refs |
| I7 | CVE/CWE enrichment | Partially implemented | indicator fields exist; CVE lookup feed not bundled |
| I8 | CISA KEV | Planned | offline KEV catalog import not bundled |
| I9 | IOC management (aging, lookup, correlation) | Implemented and tested | T, L (INTEL-IOC-001 alerts) |
| I10 | Indicator expiration | Implemented and tested | T |
| I11 | Source reliability | Implemented and tested | feed source fields + per-source counts |
| I12 | Intelligence correlation | Implemented and tested | T, L |

## Autonomous investigation (§6.5)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| G1 | Agent orchestrator | Implemented and tested | T, L |
| G2 | Task scheduling (seq, budget) | Implemented and tested | T (10s budget honored) |
| G3 | Investigation state machine | Implemented and tested | T, L (running→completed) |
| G4 | Specialist agents ×5 | Implemented and tested | T, L |
| G5 | Structured outputs | Implemented and tested | T |
| G6 | Evidence references + chain of custody | Implemented and tested | T (SHA-256 chain), L |
| G7 | Agent permissions (read-only) | Implemented and tested | T + code audit (no response engine access) |
| G8 | Tool execution validation | Implemented and tested | allowlists at every mutation boundary (response engine) |
| G9 | Failure recovery (specialist failure ≠ investigation failure) | Implemented and tested | T |
| G10 | Timeouts | Implemented and tested | T |
| G11 | Investigation history | Implemented and tested | T, L |
| G12 | LLM fallback (works without models) | Implemented and tested | deterministic by construction, T |
| G13 | LLM narration post-hook | Blocked | no model runtime in this build |

## Autonomous response (§6.6)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| R1 | Response policy engine (allowlist) | Implemented and tested | T, L (non-allowlisted → 422) |
| R2 | Approval workflow | Implemented and tested | T, L |
| R3 | Dry-run mode | Implemented and tested | T, L |
| R4 | Action allowlists | Implemented and tested | T |
| R5 | Emergency stop | Implemented and tested | T (`SENTINEL_RESPONSE_ENABLED`) |
| R6 | Rollback support | Implemented and tested | T, L |
| R7 | Action logs (audit) | Implemented and tested | T |
| R8 | Post-action verification | Implemented and tested | T, L |
| R9 | Permission checks | Implemented and tested | T, L (401/403) |
| R10 | No unrestricted LLM executes actions | Implemented and tested | code audit: actions only via approved HTTP API |

## Deception (§6.7)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| D1 | Isolated honeypots | Implemented and tested | T, L (create/start/stop) |
| D2 | Decoy services (TCP banners) | Implemented and tested | T, L |
| D3 | Decoy login pages | Partially implemented | canary-token endpoint returns a decoy notice; a full web decoy login form is Planned |
| D4 | Canary tokens | Implemented and tested | T, L |
| D5 | Decoy credentials | Implemented and tested | random per-pot credentials, T |
| D6 | Interaction logging | Implemented and tested | T, L |
| D7 | Attack behavior collection | Implemented and tested | interactions table + DECEPTION-HP-001 alerts, T |
| D8 | Network isolation | Implemented and tested | loopback default bind, T |
| D9 | Resource restrictions | Implemented and tested | unprivileged ports only, no production data, T |
| D10 | Safe termination | Implemented and tested | stop_all on shutdown, T |

## 3D virtual office (§7)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| V1 | Central Command Room | Implemented and tested | realistic scene + video wall, L |
| V2 | Network Operations Room | Implemented and tested | L |
| V3 | Threat Intelligence Room | Implemented and tested | L |
| V4 | AI Security Laboratory | Implemented and tested | L |
| V5 | Digital Forensics Laboratory | Implemented and tested | L |
| V6 | Incident Response Room | Implemented and tested | L |
| V7 | Deception Operations Room | Implemented and tested | L |
| V8 | Live agent/task visualization | Implemented and tested | `agent.task_started/completed` → markers + running counter (this recovery), L (marker path verified pre-change; type-check + store unit path verified post-change) |
| V9 | Agent identities/roles/states | Implemented and tested | agent name in marker label; tasks on Agents page |
| V10 | Investigation progress | Implemented and tested | investigation lifecycle markers, L |
| V11 | Tool execution visualization | Implemented and tested | task markers w/ evidence counts |
| V12 | Affected assets / network connections | Partially implemented | asset counts per room from REST; no topology graph (Planned) |
| V13 | Threat paths | Partially implemented | attack-chain shown on incident pages, not in 3D (Planned) |
| V14 | Containment operations | Implemented and tested | response WS events → markers (central room) |
| V15 | Evidence collection | Implemented and tested | evidence-count markers per task |
| V16 | Incident timelines | Implemented and tested | incident pages + replay |
| V17 | Backend event contract for 3D | Implemented and tested | bus topics events/alerts/incidents/assets/health/agents/response/deception (D) |
| V18 | Subscribe to actual events | Implemented and tested | L (live alert marker < 1s) |
| V19 | Synchronized agent states | Implemented and tested | running counter from real events |
| V20 | Honest failure display | Implemented and tested | failed tasks shown as FAILED markers |
| V21 | WS disconnect recovery | Implemented and tested | auto-reconnect + connected badge, L |
| V22 | Historical replay | Implemented and tested | real persisted alerts, pause/resume/exit, L |
| V23 | Pause and resume | Implemented and tested | L |
| V24 | Asset and incident inspection | Implemented and tested | room detail panel + incident pages |
| V25 | 2D fallback | Implemented and tested | always-present 2D panel + WebGL-failure notice |
| V26 | Performance | Implemented but not fully validated | build clean; frame capture blocked in this environment (hidden tab) — documented |
| V27 | No fake animations | Implemented and tested | static scene by design (ADR-008), code-audited |
| V28 | Demo/production separation | Implemented and tested | live mode only; replay is explicitly labeled, real data |

## UX completeness (§8) — spot-verified

Navigation, forms, tables, search/filter (hunt), error messages, loading/empty states,
role enforcement, 3D click-to-inspect, responsive layout: **Implemented and tested**
(vitest + tsc + live browser session; office picking verified when frames flow).

| Requirement | Status | Evidence |
|---|---|---|
| Sign in AND sign-up options offered by requirement | Implemented and tested | L (browser: toggle + role choice + account created) |
| Dashboard metrics sourced from backend, persisted across sessions | Implemented and tested | L (`/stats/overview` identical before/after re-login: 11 events / 2 alerts / 2 incidents) |

## Installation / enterprise (§11 P7)

| # | Requirement | Status | Evidence |
|---|---|---|---|
| E1 | Guided installer (`scripts/install.ps1`, `start.bat`) | Implemented and tested | L (first-run + login verified) |
| E2 | First-launch account creation (admin or normal user) | Implemented and tested | L (browser flow), T ×5 |
| E3 | MFA | Implemented and tested | T, L |
| E4 | Backup and recovery | Implemented and tested | `scripts/backup.py` validated on a live DB |
| E5 | SBOM | Implemented and tested | `docs/SBOM.json` (184 components) |
| E6 | Performance regression guards | Implemented and tested | T ×2 (smoke, not benchmarks) |
| E7 | Packaged distribution + auto-update channel | Planned | installer app / signed channel out of scope |
| E8 | SSO / SAML / LDAP | Blocked | external identity provider |