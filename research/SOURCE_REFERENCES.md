# SENTINEL-M — Source References

All sources consulted for Phase 0 research. Verification date: **2026-11-12**.

## Standards & frameworks

| # | Source | URL | Version/date verified | License |
|---|---|---|---|---|
| S1 | MITRE ATT&CK | https://attack.mitre.org/ | v20 current (Oct 13, 2026); v19 notes (Apr 28, 2026): Defense Evasion split → Stealth TA0005 + Defense Impairment TA0112; 15 Enterprise tactics | ATT&CK Terms of Use (free, attribution) |
| S2 | ATT&CK updates page | https://attack.mitre.org/resources/updates | Oct 2026 release notes; new campaigns incl. AI-assisted intrusions | — |
| S3 | OWASP Top 10 for LLM Applications 2025 (v2.0) | https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025 | PDF v2.0; LLM01 Prompt Injection → LLM10 Unbounded Consumption | CC BY-SA |
| S4 | OWASP GenAI Security Project | https://genai.owasp.org | 2026 Top 10 released; Agentic AI Top 10 (Dec 9, 2025) | CC BY-SA |
| S5 | OCSF | https://ocsf.io/ · https://github.com/ocsf/ocsf-schema | v1.5.0 current (Oct 2026) | Apache-2.0 |
| S6 | NIST CSF 2.0 | https://www.nist.gov/cyberframework | v2.0 (Feb 2024) | Public domain (NIST) |
| S7 | NIST SP 800-61r3 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | Rev. 3 (April 2025) | Public domain |
| S8 | NIST AI RMF 1.0 + AI 600-1 | https://www.nist.gov/itl/ai-risk-management-framework | AI RMF 1.0 (2023); GenAI Profile (July 2024) | Public domain |
| S9 | MITRE ATLAS | https://atlas.mitre.org/ | current 2026 | ATT&CK-style terms |
| S10 | STIX 2.1 / TAXII 2.1 | https://oasis-open.github.io/cti-documentation/ | 2.1 OASIS standards | OASIS IPR |
| S11 | Sigma | https://sigmahq.io/ | current spec | — (rule repo: Detection Rule License dsl-1.1) |
| S12 | YARA | https://github.com/VirusTotal/yara | 4.x | BSD-3 |
| S13 | CVSS v4.0 | https://www.first.org/cvss/ | v4.0 (2023) | FIRST license |
| S14 | NIST SP 800-207 (Zero Trust) | https://csrc.nist.gov/pubs/sp/800/207/final | Final (2020) | Public domain |

## Components (runtime)

| # | Component | URL | Version pinned | License |
|---|---|---|---|---|
| C1 | FastAPI | https://github.com/fastapi/fastapi | 0.141.x | MIT |
| C2 | Pydantic | https://github.com/pydantic/pydantic | 2.13.x | MIT |
| C3 | SQLAlchemy | https://github.com/sqlalchemy/sqlalchemy | 2.1.x | MIT |
| C4 | Uvicorn | https://github.com/encode/uvicorn | 0.53.x | BSD-3 |
| C5 | React | https://react.dev | 18.3.x | MIT |
| C6 | Vite | https://vite.dev | 5/6/7 latest stable | MIT |
| C7 | Tailwind CSS | https://tailwindcss.com | v4 | MIT |
| C8 | Zustand | https://github.com/pmndrs/zustand | v5 | MIT |
| C9 | Recharts | https://recharts.org | v2/v3 | MIT |
| C10 | three | https://github.com/mrdoob/three.js | 0.186.x (Phase 6) | MIT |
| C11 | @react-three/fiber | https://github.com/pmndrs/react-three-fiber | 9.8.x (Phase 6) | MIT |
| C12 | Ollama | https://ollama.com | current (Phase 3/4) | MIT |
| C13 | pytest | https://pytest.org | 8.x | MIT |
| C14 | httpx | https://github.com/encode/httpx | 0.28.x | BSD-3 |

## Verification policy

- Re-verify component versions before each phase gate; record date here.
- License changes on a dependency trigger an ADR review.
- No binary/model artifacts are downloaded without a reviewed script + checksum.
