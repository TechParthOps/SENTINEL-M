# Changelog

All notable development changes. Format loosely follows Keep a Changelog; versions are phase-gates.

## [Unreleased] - Integrations / Forensics / Reports pages, readable health (2026-11-16)

### Added
- **Integrations page** (`/integrations`): what is actually connected - available
  connectors (STIX file feeds, ingest API, WebSocket, canary endpoint), the local feed
  directory and its files, runtime posture, and the planned adapters with the exact
  external system each one needs. Nothing is listed as available unless it is running.
- **Digital Forensics page** (`/forensics`): investigation evidence chains with SHA-256
  verification, plus stored multimodal analysis and malware static-analysis records
  (hash-only). Replaces the Phase-4 planned placeholder.
- **Reports page** (`/reports`): security-posture report generated from live data
  (events, alerts by severity/status, incidents, indicators, top rules, response-action
  counts) with JSON/CSV export. Replaces the Phase-7 planned placeholder.

### Fixed
- System Health no longer dumps raw JSON per module - each module renders readable
  key/value rows (database -> url sqlite, detection -> rules loaded 19, ...).
- Settings no longer shows platform facts as raw JSON - version, environment, rule
  count and registered modules render as a proper summary with chips.
- `start.bat` now stops any already-running SENTINEL-M servers before starting (a second
  double-click used to race the first on the same database), waits for the dev server to
  listen, and auto-opens http://localhost:5173 in the browser.

## [Unreleased] - Sign up + sign in, 24-hour sessions, persisted dashboard (2026-11-15)

### Added
- The login screen offers **both options**: "Sign in" for existing accounts and
  "Create one" for self-registration (Normal user / Analyst role; honest note that
  Administrator accounts require an existing admin or the first launch). When the
  instance disables self-registration the option is hidden with an explanatory note.
- **24-hour sessions**: JWT TTL is now 1440 minutes (verified from token claims), so
  the operator stays signed in across browser restarts; the session token is kept in
  the browser's local storage and renewed on each sign-in.
- Detected activity is **persisted server-side** (SQLite), so after sign-out and
  sign-in the dashboard shows the same events, alerts and incidents - verified live
  by re-logging in and reading `/stats/overview` (11 events / 2 alerts / 2 incidents).

### Fixed
- **Startup crash on an odd-but-valid database**: `seed_if_empty` raised
  `IntegrityError: UNIQUE constraint failed: assets.hostname` (application failed to
  boot, every API call 500) when the database held the sample inventory with zero
  users - e.g. after a partially seeded file or a stale-instance race. Seeding is now
  idempotent per row and never aborts startup. Reproduced on the exact failing state
  (0 users / 6 assets) and verified to boot cleanly afterwards.

### Verification
- Browser: login screen shows Sign in + "Create one"; sign-up screen renders role
  choice and creates an analyst account end-to-end.
- REST: first-launch admin, token TTL = 24 h, dashboard counts identical before and
  after re-login.
- Backend pytest: **124/124 passed** (adds session-TTL + token-expiry tests).
  Frontend: vitest 7/7, tsc clean, build clean.

## [Unreleased] - Master-prompt audit recovery (2026-11-15)

### Added
- 3D office now visualizes **agent task lifecycle**: `agent.task_started`,
  `agent.task_completed` and `investigation.status_changed` frames become live markers
  in the Incident Response room (agent name, FAILED states, evidence counts), with a
  running-task counter in the office header. Previously only investigation lifecycle
  was rendered - the backend already published these events.
- `docs/IMPLEMENTATION_MATRIX.md`: full requirement-to-implementation matrix with
  evidence-based statuses (audit of the master prompt §6/§7 checklist).
- `docs/RECOVERY_REPORT.md`: recovery record for this cycle.

### Verified
- Live: during a real investigation on a running server, agent task markers
  (`alert_triage started` ... `synthesis done (N evidence)`, `investigation.completed`)
  streamed into the office's live marker list over WS.
- Backend pytest: **122/122 passed**; frontend vitest 7/7; `tsc -b` clean; build clean.

## [Unreleased] - First-launch account creation

### Changed
- **No printed credentials.** On a fresh install the platform no longer invents an
  admin password: the first launch shows an account-creation screen where the
  operator chooses **Administrator** or **Normal user** and sets their own password.
  Credentials live only in the local database. (`SENTINEL_SEED_ADMIN_PASSWORD`
  still works for headless/CLI bootstrapping; see docs/INSTALL.md.)
- `POST /auth/users` accepts any role for the **first** account only (bootstrap,
  no admin token needed, audit-recorded); once any user exists the previous rules
  apply unchanged. New public `GET /auth/bootstrap-status`.
- Login page redirects an already-signed-in user to the app; after sign-out the
  sign-up screen stays gone while accounts exist.
- `start.bat` keeps its final window open (pause) with the URL and first-launch
  instructions, so nothing disappears before it can be read.

### Verification
- Browser end-to-end: first-launch screen -> create Administrator -> auto sign-in ->
  dashboard; sign out -> normal login (no sign-up) -> sign back in -> dashboard.
- Backend pytest: **122/122 passed** (adds 5 bootstrap tests).
- A logged-in session visiting `/login` is redirected to `/overview`.

## [Unreleased] - Developer experience: one-click starter

### Added
- `start.bat` (Windows one-click starter): creates the backend virtual environment,
  installs dependencies, seeds `backend\.env` from the example, starts the backend with
  `uvicorn --reload` and the frontend with Vite HMR, and prints the URL. The script
  auto-selects a free port when the preferred one is still held by the OS after a
  force-stop. Modes: `start.bat`, `--update` (git pull + dependency sync first),
  `--auto-update` (updater window polling git every 5 minutes; changed code is applied
  live by --reload/HMR, dependencies reinstall only when requirements/package.json
  change), `--stop`.
- `scripts/auto_update.bat`: companion poller for `--auto-update`; states clearly when
  no git remote is configured and still detects local commits.

## [0.7.0] - Phase 7: Enterprise Readiness (partial) - 2026-11-14

### Added
- **MFA (TOTP, RFC 6238, stdlib-only)**: `app/core/mfa.py` (secret generation, code
  verification with +/-1 step drift, provisioning URI, single-use recovery codes stored
  as SHA-256 hashes) + `/auth/mfa/*` endpoints. Login with MFA enabled returns a
  5-minute **step-up token** that is rejected by every normal endpoint - the second
  factor is mandatory, not optional. `users` columns + additive migration.
  Settings page enrollment panel + login second-factor step.
- **Local installer**: `scripts/install.ps1` (deps, `.env` generation with a real secret
  key + seed admin password, DB init, build, HTTP self-check).
- **Backup tool**: `scripts/backup.py` (consistent online backup with WAL checkpoint,
  table sanity check, rolling retention) - verified against a real 304 kB database.
- **SBOM**: `scripts/generate_sbom.py` -> `docs/SBOM.json` (CycloneDX 1.5, 184 components
  from installed package metadata - truthful inventory).
- **Performance smoke**: `backend/tests/test_performance.py` (regression guards with
  generous bounds - explicitly not benchmarks).

### Verification
- Backend pytest: **117/117 passed** (adds 5 MFA + 2 performance tests).
- Frontend vitest 7/7; `tsc -b` clean; production build clean.
- Live MFA smoke (`scripts/mfa_smoke.ps1` on a real server): enroll -> activate ->
  login -> step-up token rejected on `/auth/me` (401) -> TOTP verify -> full session ->
  recovery login -> reused recovery code rejected (401) -> disable.
- Installer DB init sequence executed for real; backup tool produced and validated a
  consistent copy of the live database.

### Honest gaps (documented, not claimed)
- No automated update mechanism or packaged distribution (no GUI installer).
- No SSO/SAML/LDAP or ticketing/chatops integrations (external providers).
- Performance tests are regression guards, not benchmark results for a specific workload.

## [0.6.0] - Phase 6: 3D Virtual Security Operations Office - 2026-11-14

### Added
- 3D virtual office (Phase 6): R3F scene (`frontend/src/components/OfficeScene.tsx`, 7 rooms,
  orbit camera, activity pillars) driven strictly by real telemetry - room counts from REST
  (`stats/overview`, `agents/investigations`, `intel/status`, `deception/pots`,
  `aisec/analyses`, `media/analyses`, `health`, `alerts`), live markers only from WS-confirmed
  frames (alerts/incidents/agents/response/deception).
- Historical replay of **real persisted alerts** (pause/resume/exit) over the same viewer;
  guaranteed 2D fallback panel with identical data and an explicit WebGL-failure notice.
- Route `/virtual-office` wired; nav item flipped from planned to implemented.
- **Realistic security-operations environment** (upgrade): partitioned rooms with door gaps
  and glass strips, wall signage, desks with monitors and chairs, desk-mounted activity
  beacons (glass tube + emissive core scaled by real volume), a Central Command **video wall**
  (one screen per room with name + live count), ceiling beams, perimeter walls, and an open
  collaboration area. Screens, beacons and signage show REAL numbers only; the scene is
  static (no animation, no simulated staff).

### Honesty contract
- No simulated avatars, no fake attack animation. Declined by design; recorded in
  coverage/phase docs.
- Live verification against a real uvicorn server (fresh DB, seeded admin): room counts matched
  the actual alert/indicator/investigation rows; a newly ingested FILE-RANSOM-001 alert appeared
  in the live WS stream as a marker in Digital Forensics Lab; replay stepped 1/6 -> 6/6 over the
  persisted alert list; the realistic environment loads with zero console errors.
- **Environment limitation (recorded, not hidden):** the in-app browser session runs with a
  hidden tab, so `requestAnimationFrame` never fires there and the WebGL canvas cannot paint a
  frame - pixel/screenshot capture and 3D pointer-picking could not be exercised in this
  session. The new environment is validated by TypeScript/build gates, a clean mount with zero
  console errors, and the real-data layer (all seven REST endpoints polled with 200s on a live
  server); the earlier office build was verified end-to-end in this same harness when frames
  flowed.

### Verified
- Frontend `tsc -b` clean, vitest 7/7, production build clean (chunk-size warning: three.js).

## [0.5.0] - Phase 5: Response & Deception - 2026-11-14

### Added
- Response engine (`app/response/`): allowlisted action types (isolate asset, block IOC, disable
  user, quarantine file, kill process, snapshot host), autonomy levels L0/L1/L2, analyst request ->
  admin approval -> execution -> verification -> rollback, dry-run mode, denylist, and
  `SENTINEL_RESPONSE_ENABLED` emergency stop. `assets.isolated` column added with migration for
  pre-existing DBs. API `/response/*` + Response page.
- Deception engine (`app/deception/`): loopback-by-default honeypots (`SENTINEL_DECEPTION_BIND`),
  random decoy credentials, canary tokens, TCP banner interaction capture emitting
  DECEPTION-HP-001 alerts and `deception.*` WS topics, safe stop on shutdown. API
  `/deception/*` + Deception page.

## [0.4.0] - Phase 4: Autonomous Investigation - 2026-11-14

### Added
- Agent orchestrator (`app/agents/`) with five deterministic, read-only specialists
  (alert_triage, asset_context, intel_check, related_activity, synthesis), per-investigation
  SHA-256 evidence chain, 10s time budget, and `agents` WS bus topic. No LLM required.
  API `/agents/*` + Agents page.
- Threat hunting API (`/hunt`: IOC/entity/class/time-range sweeps over retained events + alerts)
  + Hunt page.

## [0.3.0] - Phase 3: AI & Multimodal Defense - 2026-11-14

### Added
- AI-security engine (`app/aisec/`): deterministic text analysis with per-finding confidence -
  direct/indirect prompt injection, jailbreak/extraction, RAG-poisoning indicators,
  data-disclosure (API keys, tokens, credential pairs), tool-override instructions,
  phishing/BEC markers (urgency, authority, lures, link indicators). OWASP LLM + MITRE ATLAS
  references on findings. API `/aisec/*` + AI Security page.
- Multimodal engine (`app/multimodal/`): kind-routed in-memory analysis, bytes never stored -
  image (metadata/EXIF, generative-AI tool strings, QR payload threat analysis via OpenCV,
  recompression probe), audio (WAV/PCM statistics with low-confidence synthetic-speech
  indicators; MP3/OGG honestly unsupported), video (OpenCV-decodable frame statistics;
  no neural detectors - stated limitation), document (PDF action-object scan + OOXML parts).
  API `/media/*` + Multimodal Forensics page.
- MalwarePage restored at `/malware` (it had been parked at `/multimodal`); title corrected.
- Health registry now covers ai_security and multimodal.

### Verification
- Backend pytest: **91/91 passed** (adds 8 AI-security + 10 multimodal tests).
- Frontend vitest: **7/7 passed**; production build clean.
- Live HTTP smoke: email-context analysis -> high_risk (phishing + injection + tool override);
  QR PNG analysis -> both QR findings detected; health registry reports new modules ok.

### Honest limitations (documented)
- No OCR (no tesseract binary in build), no neural deepfake/synthetic-speech detectors,
  no MP3/OGG decode, no bundled face-detection model (OpenCV 5 wheels ship no cascades).
- All AI findings are heuristic evidence strengths, never intent/identity verdicts.

## [0.2.0] - Phase 2: Traditional Cyber Defense - 2026-11-14

### Added
- Detection rule set expanded to 18 JSON rules: C2 beaconing, DGA/DNS-tunnel indicators,
  exfiltration volume, XSS/SSRF/path traversal, service creation, Run-key persistence,
  credential-dumping indicators, impossible travel. Rule engine gained composite `group_by`,
  numeric `where_gte` comparisons and derived telemetry fields (DNS label entropy, volumes).
- Identity engine (`app/identity/`): cross-session auth correlation (successive-login geo change)
  feeding ID-IMPOSSIBLE-TRAVEL-001; identity summary API + frontend page.
- Malware static-analysis engine (`app/malware/`): hashes, entropy, PE parsing, strings,
  archives, Office macros, signal scoring; file-analysis API + Multimodal Forensics page.
  Hash-only evidence (no byte retention).
- Threat-intelligence engine (`app/intelligence/`): STIX 2.1 import, indicator aging,
  event enrichment -> INTEL-IOC-001 alerts, offline feed directory, admin import/reload APIs
  + Threat Intelligence page.
- Phase-2 frontend pages: Network Security, Endpoint Security, Identity Security,
  Threat Intelligence; `/multimodal` route corrected to an honest Planned panel.

### Verification
- Backend pytest: **73/73 passed** (adds Phase-2 rule, intel, malware, identity tests).
- Frontend vitest: **7/7 passed**; production build clean.

## [0.1.0] - Phase 1: Core Platform - 2026-11-13

### Added
- Phase 0 research library (`research/`): standards adoption (ATT&CK v20, OCSF 1.5.0, OWASP LLM
  2025/2026, NIST CSF 2.0, SP 800-61r3, AI RMF), technology comparison, 10 ADRs, coverage matrix,
  component selection, source register.
- Backend core (FastAPI + SQLAlchemy/SQLite WAL):
  - JWT auth (HS256, in-repo stdlib implementation), PBKDF2 password hashing, RBAC roles.
  - Asset inventory API (manual + telemetry auto-registration with honest source flags).
  - Event ingestion gateway (batch 1-1000, authenticated, rate-limited) + OCSF-aligned normalization
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
    "Planned - Phase N" panels (ADR-010).
  - Overview dashboard (live metrics + charts), Live Operations (WebSocket + REST feed),
    Threat Detection (alerts + workflow), Incidents list + evidence detail, Assets, Detection
    Rules, System Health + audit view, Capabilities matrix (live coverage data), Settings.
- Docs: `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/REPORTS/phase1_report.md`, root README/SECURITY.
- Verification scripts: `scripts/smoke_test.ps1` (live attack sequence), `scripts/e2e_frontend.ps1`
  (API + SPA through the dev proxy).

### Verification
- Backend pytest: **39/39 passed**.
- Frontend vitest: **7/7 passed**; production build clean (0 TS errors).
- Live-suite: 53-event attack sequence -> 5 alerts across 5 rules, escalated chain incident
  (sev 6, 3 ATT&CK techniques) with 3 evidence-linked alerts; audit hash chain valid;
  unauthorized requests rejected 401; viewer role denied alert mutations 403.

### Security
- Rate limiting on auth + ingestion; strict Pydantic validation at every boundary; audit records
  for all state-changing calls; seeded sample assets flagged `sample` in UI (ADR-008).
