# SENTINEL-M - Installation & Operations Guide

**Status:** Phase 7 partial · local-first deployment (no external services required)

## Quick install (Windows / PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The installer will:

1. install backend dependencies (`backend/requirements.txt`),
2. generate `backend/.env` with a random `SENTINEL_SECRET_KEY` and a seed admin
   password (an existing `.env` is never overwritten),
3. initialize the database (additive migrations -> schema -> sample inventory -> STIX feeds)
   and build the frontend,
4. run an HTTP self-check against the freshly created app.

## Run

```powershell
cd backend
python -m uvicorn app.main:app --port 8942   # 8000 may be blocked on some Windows hosts
```

```powershell
cd frontend
npm run dev       # dev server, proxies /api and /ws to the backend (VITE_API_TARGET)
# or:  npm run preview  (serves the production build)
```

Open `http://localhost:5173` and sign in with the seed admin password printed into
`backend/.env` at install time. **Change the password on first login** (Settings page);
the backend also flags insecure default secrets loudly in the startup log.

## Configuration (`SENTINEL_*` environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_SECRET_KEY` | insecure default | JWT signing key - **must** be set for real use |
| `SENTINEL_SEED_ADMIN_PASSWORD` | random, printed once | first-boot admin password (fresh DB only) |
| `SENTINEL_DB_URL` | `sqlite:///<data_dir>/sentinel.db` | database location |
| `SENTINEL_DECEPTION_BIND` | `127.0.0.1` | honeypot bind address (loopback isolation default) |
| `SENTINEL_RESPONSE_ENABLED` | `true` | emergency stop for real response actions |
| `SENTINEL_TEST_INTEL_FEEDS_DIR` | - | tests only: STIX feed directory override |

## Operations

- **Backup:** `python scripts/backup.py --out backups --keep 7` - consistent online
  backup of the database (WAL checkpointed, rolling retention). The secret key/env file
  is **not** part of the backup and must be preserved separately.
- **SBOM:** `python scripts/generate_sbom.py` -> `docs/SBOM.json` (CycloneDX 1.5).
- **Rebuild coverage docs:** `backend/app/coverage.json` is the machine twin of
  `research/THREAT_COVERAGE_MATRIX.md`; `tests/test_system.py` enforces they stay in sync.
- **MFA:** Settings -> Two-factor authentication (TOTP authenticator app; recovery codes
  are printed once). Session tokens require the second factor at every login.

## Not in this build (honest)

- No packaged installer app or auto-update mechanism.
- No SSO/SAML/LDAP federation, ticketing or chatops integrations.
- No reverse-proxy/TLS termination guidance beyond "put it behind your own proxy" -
  the app binds localhost by default and expects a local-first deployment.