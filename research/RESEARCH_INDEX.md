# SENTINEL-M Research Index

**Project:** SENTINEL-M — Autonomous Multimodal Cyber Defense System
**Maintained by:** SENTINEL-M engineering
**Last full review:** 2026-11-12
**Status:** Living document. Every claim in this file must carry a source in `SOURCE_REFERENCES.md`.

---

## Purpose

This directory records the research that backs every architectural and dependency decision in
SENTINEL-M. No component is adopted without: (1) a verified source, (2) a license check,
(3) a recorded verification date, and (4) a stated reason for selection over alternatives.

## Document map

| Document | Contents |
|---|---|
| `TECHNOLOGY_COMPARISON.md` | Alternatives considered per layer (backend, frontend, AI/ML, detection) and why choices were made |
| `SECURITY_STANDARDS.md` | Standards adopted (NIST CSF 2.0, ATT&CK, OWASP, STIX 2.1, OCSF, Sigma, YARA…), versions and verification dates |
| `THREAT_COVERAGE_MATRIX.md` | Threat classes → detection engine → telemetry source → ATT&CK mapping → current status |
| `ARCHITECTURE_DECISIONS.md` | Numbered ADRs (Architecture Decision Records) |
| `SOURCE_REFERENCES.md` | Canonical list of all sources with URLs, versions, licenses, verification dates |
| `COMPONENT_SELECTION.md` | Concrete dependency list with pinned versions, license, and justification |

## Key research findings (verified 2026-11-12)

1. **MITRE ATT&CK v20 (Oct 13, 2026)** is the current Enterprise release. As of v19 (April 2026),
   the Enterprise Defense Evasion tactic was split into **Stealth (TA0005)** and a new
   **Defense Impairment (TA0112)** tactic — Enterprise now has 15 tactics. Detection mappings in
   SENTINEL-M must support both the new tactic set and emit mappings legible to older tooling.
2. **OWASP Top 10 for LLM Applications 2025 (v2.0)** is the reference list for AI-application
   risks (LLM01 Prompt Injection … LLM10 Unbounded Consumption). A **2026 edition** exists with
   reordering — Excessive Agency rose to a top-3 risk — and OWASP now publishes separate
   **Agentic AI** guidance (Dec 2025). SENTINEL-M's AI Security Engine tracks both.
3. **OCSF 1.5.0** is the current Open Cybersecurity Schema Framework release. SENTINEL-M's
   normalized event model is an OCSF-aligned subset (see ADR-004).
4. **React Three Fiber 9.8.x / three 0.186.x** are current for the 3D virtual operations
   environment (Phase 6). R3F's React-scheduling model outperforms naive imperative Three.js at
   scale and is the correct choice for data-driven scenes.
5. **Local-first AI is feasible on the target hardware.** The dev workstation has an RTX 3050
   6GB laptop GPU. This constrains local model choices to small classifiers (ONNX Runtime CPU/GPU)
   and 3–8B class LLMs via Ollama (quantized). No paid cloud AI API is required for core function.

## Research discipline rules

- Versions are re-verified before each phase gate; the verification date is recorded.
- We do **not** auto-download repositories, executables, or model weights. Fetches happen via
  reviewed scripts in `scripts/` with checksum verification.
- If a source contradicts an existing decision, the ADR is revisited, not silently patched.
