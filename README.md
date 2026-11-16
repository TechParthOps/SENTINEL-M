# SENTINEL-M

**Autonomous Multimodal Cyber Defense, Threat Intelligence & 3D Virtual Security Operations Platform**

SENTINEL-M is a local-first, modular cybersecurity platform that ingests security telemetry,
normalizes it to an OCSF-aligned schema, detects threats with deterministic explainable rules,
correlates alerts into incidents with evidence-backed narratives, and - in later phases - adds
AI/LLM security, multimodal forensics, autonomous investigation agents, controlled response,
deception technology, and a live 3D virtual security-operations environment driven by real data.

> **Honesty principle:** every metric in the UI comes from real application data or is explicitly
> labeled as planned/simulated. Planned capabilities are never presented as implemented.

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Research, architecture, standards | ✅ Complete |
| 1 | Core platform: auth, DB, ingestion, normalization, detection, correlation, WebSocket, dashboard | ✅ Implemented & tested |
| 2 | Traditional cyber defense (network/endpoint/intel engines, adapters) | ✅ Implemented & tested |
| 3 | AI & multimodal security (prompt injection, QR, image/audio/video forensics) | ✅ Implemented & tested |
| 4 | Autonomous investigation agents (deterministic, read-only, evidence-chained) | ✅ Implemented & tested |
| 5 | Controlled response & deception (allowlist + approval + verification + rollback) | ✅ Implemented & tested |
| 6 | 3D virtual security-operations office (live-synced to real data, replay, 2D fallback) | ✅ Implemented & tested |
| 7 | Enterprise readiness: MFA (TOTP), local installer, backup, SBOM, performance smoke | 🟡 Partial (packaging + SSO honestly deferred) |

The authoritative capability matrix lives in
[`research/THREAT_COVERAGE_MATRIX.md`](research/THREAT_COVERAGE_MATRIX.md) and is rendered
in-product on the Capabilities page. See [`docs/REPORTS/FINAL_REPORT.md`](docs/REPORTS/FINAL_REPORT.md)
for the full development report and release-readiness classification.

## Quick start (development)

**One click (Windows):** double-click **`start.bat`** — it creates the virtual
environment, installs dependencies, starts the backend (auto-reload) and the frontend
(hot reload), stops any previous SENTINEL-M servers, and opens
http://localhost:5173 in your browser. Variants: `start.bat --update` (pull latest code
first), `start.bat --auto-update` (keeps pulling git every 5 min; servers pick up changes
live), `start.bat --stop`. See [`docs/INSTALL.md`](docs/INSTALL.md).

Prerequisites: Python 3.11+, Node.js 20+.

```powershell
# 1. Backend
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env   # then edit SECRET_KEY
uvicorn app.main:app --reload --port 8942   # 8000 can be blocked on some Windows hosts

# 2. Frontend (second terminal)
cd frontend
npm install
$env:VITE_API_TARGET="http://127.0.0.1:8942"; $env:VITE_WS_TARGET="ws://127.0.0.1:8942"
npm run dev              # http://localhost:5173

# 3. Tests
cd backend && python -m pytest -q
cd frontend && npm test
```

First run creates `backend/data/sentinel.db` and shows a **first-launch screen**: create
the first account (Administrator or Normal user) with a password you choose — nothing is
printed or emailed. After that, the login screen offers **both** Sign in and Create
account; sessions last 24 hours and all detected activity stays on your dashboard.

## Documentation

- [`research/`](research) - standards, comparisons, ADRs, coverage matrix, sources
- [`docs/`](docs) - architecture, API guide, reports, install guide
- [`SECURITY.md`](SECURITY.md) - responsible disclosure & security model
- [`CHANGELOG.md`](CHANGELOG.md) - development history

## License

See [LICENSE](LICENSE).
