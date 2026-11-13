# SENTINEL-M — Component Selection

**Last verified:** 2026-11-12. Pinned versions live in `backend/requirements.txt` and
`frontend/package.json`; this file records the *why* and the *constraints*.

## Phase 1 dependency set (now)

| Component | Why selected | Constraint / risk | Mitigation |
|---|---|---|---|
| FastAPI + Uvicorn | Async, WS-native, OpenAPI docs, team skill | Single-process CPU bound | Workers per module in later phases |
| SQLAlchemy 2.1 | Same models run on SQLite & PostgreSQL | ORM learning curve | Keep queries simple, indexed |
| Pydantic 2.x | Strict API validation at the trust boundary | v1→v2 syntax | v2-only codebase from day one |
| stdlib JWT/PBKDF2 (in-repo) | Zero supply-chain surface, fully auditable | Must implement carefully | Security tests in `tests/test_auth*` |
| React 18 + TS + Vite | R3F-compatible, fast, typed | npm churn | Lockfile committed |
| Tailwind v4 | Fast consistent styling, dark SOC theme | Class soup risk | Component primitives in `components/ui` |
| Zustand | Minimal store for live event streams | — | Slices per domain |
| Recharts | Declarative dashboards | Bundle size | Route-level code splitting |
| pytest + httpx | Test the API as a black box | — | Coverage gates per phase |

## Deferred (phase-gated, not installed yet)

| Component | Phase | Note |
|---|---|---|
| three / @react-three/fiber / drei | 6 | Versions verified: three 0.186.x, R3F 9.8.x |
| Ollama client | 3–4 | Local-only LLM; optional, system must run without it |
| ONNX Runtime + tokenizer libs | 3 | Small classifiers for prompt-injection/phishing |
| OpenCV / librosa | 3 | Image/audio forensics |
| YARA (python bindings) | 2 | File scanning |
| sigma-cli / pySigma | 2 | Rule conversion |
| Suricata/Zeek log shippers | 2 | File-tail adapters, no process coupling |
| Wazuh API client | 2 | Adapter pattern |
| PostgreSQL | 7 | Config switch via SQLAlchemy URL |

## Explicitly rejected

| Component | Reason |
|---|---|
| Paid LLM APIs as core dependency | Violates local-first principle; optional plugin only |
| Kafka/Flink | Ops burden unjustified at this scale (ADR-001/007) |
| Electron desktop wrapper | Web UI + installer covers the need; revisit post-Phase 7 |
| GPL-linked libraries inside core code | License hygiene — adapters consume external tools via APIs/files instead |
