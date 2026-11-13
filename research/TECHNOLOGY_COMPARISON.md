# SENTINEL-M — Technology Comparison

**Last verified:** 2026-11-12

Each section lists the realistic options considered, the decision, and the deciding factors.
Decisions are cross-referenced to ADRs in `ARCHITECTURE_DECISIONS.md`.

---

## 1. Backend framework

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **FastAPI (Python)** | Async-first, native WebSockets, Pydantic validation, huge ecosystem for security/ML (YARA, scikit-learn, transformers all Python-first), OpenAPI docs free | Single-language GIL for CPU-bound work (mitigated by workers) | **Selected** |
| Go (chi/gin) | Excellent concurrency, single binary | ML/AI ecosystem far weaker; two languages for one platform | Rejected for core |
| Node.js (NestJS) | Shared language with frontend | Security tooling (YARA, Zeek log parsing, ML) much weaker | Rejected |
| Java/Spring | Enterprise maturity | Heavy, slow iteration for this team size | Rejected |

## 2. Database

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **SQLite (dev / single-node)** | Zero-admin, local-first, fine for ≤ millions of events with WAL + indexes | Concurrent writers limited | **Selected for Phase 1** |
| PostgreSQL (production) | Real concurrency, JSONB, partitioning | Requires a service; not needed until multi-node/enterprise | **Selected for Phase 7+** (same SQLAlchemy models) |
| Time-series DB (ClickHouse) | Fast aggregation over events | Extra infrastructure; premature | Deferred |

## 3. Frontend

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **React 18+ + TypeScript + Vite** | Ecosystem, R3F requires React, fast HMR, TS safety | — | **Selected** |
| Svelte/SvelteKit | Smaller bundles | R3F ecosystem is React-native; team constraint | Rejected |
| Angular | Enterprise structure | Heavier, weaker 3D ecosystem | Rejected |

**State:** Zustand (tiny, no boilerplate, works well with R3F's `useFrame` loops where Redux re-renders hurt).
**Charts:** Recharts (React-native, declarative). Alternatives: ECharts (more powerful, heavier), visx (lower-level). Recharts covers Phase 1 dashboards; revisit if heatmap/attack-graph needs exceed it.
**3D:** three 0.186 + @react-three/fiber 9.8 + drei. Alternatives: Babylon.js (great engine, weaker React integration), plain Three.js (fine but we want declarative data binding for the digital twin). Deferred to Phase 6 — not installed yet (YAGNI).

## 4. Authentication & secrets

| Option | Verdict |
|---|---|
| **PBKDF2-HMAC-SHA256 (stdlib `hashlib`)** — 600k iterations, per-user salt | **Selected** (ADR-002). Zero native deps, FIPS-friendly, no Windows build pain |
| bcrypt/argon2 (passlib) | Better GPU resistance for argon2; native wheels historically fragile on Windows/Py3.11 combos. Revisit at enterprise hardening |
| OAuth2/OIDC (Keycloak) | Right answer for enterprise SSO — Phase 7 integration, not core dependency |

JWT: HS256 implemented in-repo on top of stdlib `hmac` (ADR-003) to keep the dependency surface
minimal and auditable. Swappable for PyJWT/OIDC later behind `core/security.py`.

## 5. Event normalization

| Option | Verdict |
|---|---|
| **OCSF-aligned subset (own canonical model)** | **Selected** (ADR-004). OCSF 1.5.0 taxonomy (class_uid, severity_id, activity_id, observables) adopted conceptually; full schema import deferred |
| Full OCSF schema validation (ocsf-schema JSON) | Adopt when integration adapters (Wazuh/Suricata/Zeek) land in Phase 2 |
| ECS (Elastic) | Elastic-coupled taxonomy; OCSF is the vendor-neutral successor trend |

## 6. Detection engineering

| Option | Pros | Cons | Verdict |
|---|---|---|---|
| **In-repo rule engine + JSON rules** | Deterministic, testable, explainable, no runtime deps | We must build it | **Selected** (ADR-005) |
| Sigma-only | Standard, huge rule corpus | Needs a converter + backend engine anyway; adoption planned as *import target* in Phase 2 | Partial adopt |
| Stream-processing (Flink/Kafka) | Scales massively | Massive ops burden for a local-first product | Rejected for core |

## 7. AI/ML stack (Phases 3–4)

| Concern | Selected | Alternatives rejected/deferred |
|---|---|---|
| Local LLM runtime | **Ollama** (OpenAI-compatible API, quantized 3–8B models fit 6GB VRAM) | llama.cpp direct (lower-level than needed), paid APIs (violates local-first) |
| Prompt-injection / text classifiers | ONNX Runtime + small transformer classifiers (e.g., deberta-mini class) | Full PyTorch serving (heavy for inference-only) |
| Vision/audio forensics | OpenCV + librosa + targeted ONNX models | End-to-end deepfake SOTA models (research-grade, GPU-hungry) — documented limitation |
| Classical ML | scikit-learn (baselines, anomaly detection) | — |

## 8. Telemetry integrations (Phase 2+, all optional adapters)

| Source | Role | Notes |
|---|---|---|
| Wazuh | Endpoint + FIM + rules | GPL v2 — adapter consumes its API/feeds, does not link its code |
| Sysmon | Windows process/registry/network events | XML config shipped in-repo |
| osquery | Cross-platform endpoint SQL telemetry | Apache-2.0 |
| Zeek | Network metadata logs | BSD |
| Suricata | NIDS alerts + EVE JSON | GPL v2 — adapter consumes EVE output only |
| Velociraptor | DFIR collection | AGPL — run as external tool, no code linkage |
| OpenCTI / MISP | Threat intel | Consume their APIs |

Licensing note: adapters communicate over documented interfaces (files/APIs); SENTINEL-M code
does not derive from GPL sources, keeping the core license choice free (see LICENSE).
