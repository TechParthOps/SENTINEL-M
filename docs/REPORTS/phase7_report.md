# Development Report - Phase 7: Enterprise Readiness (partial)

**Date:** 2026-11-14 · **Milestone:** Phase 7 · **Status:** complete within documented scope
(MFA, install, backup, SBOM, performance smoke); packaging + SSO honestly deferred

## What was implemented

1. **Multi-factor authentication** (`app/core/mfa.py`, `/auth/mfa/*`):
   - TOTP per RFC 6238 (HMAC-SHA1, 30 s step, 6 digits, +/-1 step drift) implemented on
     the standard library only - no new runtime dependency, fully offline.
   - Enrollment: `POST /auth/mfa/setup` returns the secret, an `otpauth://` provisioning
     URI and **5 single-use recovery codes** (shown once; stored as SHA-256 hashes).
     MFA stays disabled until `POST /auth/mfa/activate` succeeds with a live code, so a
     half-finished enrollment can never lock an operator out.
   - Login: with MFA on, `POST /auth/login` returns `mfa_required: true` and a 5-minute
     **step-up token** (`scope: "mfa"`). `get_current_user` rejects step-up tokens
     (401) - verified live - so the second factor cannot be skipped.
   - Recovery: single-use codes at `/auth/mfa/recovery-login`; reuse returns 401.
   - Disable requires the current password **and** a live code.
   - Rate limits: 10/min on verify, 5/min on recovery login.
   - DB: `users.mfa_secret/mfa_enabled/mfa_recovery/mfa_enrolled_at` with an additive
     migration (`_run_migrations`) - applied live to a pre-MFA database.
   - Frontend: login second-factor step (code or recovery code) + Settings enrollment panel.
2. **Local installer** (`scripts/install.ps1`): dependencies -> `.env` (generated secret
   key + seed admin password; never overwrites an existing `.env`) -> DB init
   (migrations + create_all + seed + STIX feed load) -> frontend build -> HTTP self-check.
3. **Backup tool** (`scripts/backup.py`): consistent online backup (WAL checkpoint via
   the SQLite backup API), table sanity check, rolling retention. Verified against the
   real 304 kB database.
4. **SBOM generator** (`scripts/generate_sbom.py`): CycloneDX 1.5 JSON from installed
   package metadata - `docs/SBOM.json`, 184 components. Truthful: it is what actually
   runs, not a curated list.
5. **Performance smoke** (`backend/tests/test_performance.py`): regression guards on
   500-event batch ingest and a repeated-detection batch with generous, clearly-labeled
   bounds (30 s / 20 s). Explicitly **not** a benchmark; suites run in seconds on the
   development machine.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest (adds `test_mfa.py` ×5, `test_performance.py` ×2) | **117/117 passed** |
| `frontend`: vitest / `tsc -b` / build | **7/7 passed**; type-check clean; build clean |
| Live MFA smoke (`scripts/mfa_smoke.ps1`): enroll -> step-up rejected (401) -> verify -> recovery single-use -> disable | passed |
| Live installer DB-init + backup against the real database | passed |
| Phase-6 stale coverage test fixed (asserts implemented + declined item marked planned) | passed |

## Honest gaps

- **No installer packaging / auto-update**: no PyInstaller/Electron packaging, no
  update channel; the script is a developer/local installer. Left `planned` in coverage.
- **No SSO/SAML/LDAP, no ticketing/chatops**: requires external providers; left `blocked`.
- MFA protects the web session; there is no hardware-key (WebAuthn/FIDO2) support.