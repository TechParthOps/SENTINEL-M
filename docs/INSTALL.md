# SENTINEL-M - Installation & Operations Guide

**Status:** Phase 7 partial · local-first deployment (no external services required)

## Quick start (Windows) — one click

```bat
start.bat
```

That is all a user needs. The script:

1. creates `backend\.venv` and installs backend/frontend dependencies on first run,
2. copies `.env.example` to `backend\.env` if no environment file exists (edit it to
   set `SENTINEL_SECRET_KEY`),
3. starts the backend (`uvicorn --reload` → changes to Python code are applied
   automatically) and the frontend (Vite dev server with hot reload),
4. opens nothing itself — browse to **http://localhost:5173** and sign in.

Variants:

| Command | Effect |
|---|---|
| `start.bat` | start both servers with live reload |
| `start.bat --update` | `git pull` the latest code, sync dependencies, then start |
| `start.bat --auto-update` | also opens an updater window that pulls git every 5 minutes; changed code is picked up automatically by `--reload` / HMR |
| `start.bat --stop` | stop the servers on the backend/dev ports |

## Manual quick start (Windows / PowerShell)

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

Open `http://localhost:5173`. On first launch the page asks you to **create the first
account** — Administrator (full access: response actions, users, deception) or Normal user
(read-only) — with a password you choose. Nothing is printed or emailed; credentials live
only in the local database, and the sign-up screen is never shown again while any account
exists. **Change the password on first login** if you want (Settings page); the backend
also flags insecure default secrets loudly in the startup log.

Headless / CLI installs can still bootstrap an admin automatically by setting
`SENTINEL_SEED_ADMIN_PASSWORD` in `backend/.env` before the first start (the seeded
account is created with `must_change_password=True`).

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