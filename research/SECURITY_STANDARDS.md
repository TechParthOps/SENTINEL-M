# SENTINEL-M — Security Standards Adoption

**Last verified:** 2026-11-12

| Standard / Knowledge base | Version used | Role in SENTINEL-M | Verification |
|---|---|---|---|
| NIST Cybersecurity Framework | 2.0 (Feb 2024) | Governs, Identify, Protect, Detect, Respond, Recover mapping for capability coverage reporting | Status confirmed via NIST CSF 2.0 publication |
| NIST SP 800-61 | Rev. 3 (April 2025) — Computer Security Incident Handling Guide | Incident lifecycle model (Preparation → Detection & Analysis → Containment/Recovery → Post-Incident) drives Incident workflow states | Phase 1 incident states align to Rev.3 model |
| MITRE ATT&CK Enterprise | **v20 (Oct 13, 2026)** | Technique taxonomy for every alert/detection. Note: v19+ Enterprise has 15 tactics — Defense Evasion split into **Stealth (TA0005)** and **Defense Impairment (TA0112)** | attack.mitre.org/resources/updates (Oct 2026) |
| MITRE ATT&CK Mobile / ICS | v20 | Deferred applicability (IoT/OT roadmap) | — |
| MITRE ATLAS | current (2026) | Adversarial ML technique taxonomy for AI Security Engine findings | atlas.mitre.org |
| OWASP Top 10 (Web) | 2021 → 2025 edition when finalized | Web/API risk categories for Application Security Engine | Monitored |
| OWASP API Security Top 10 | 2023 | API risk taxonomy | Monitored |
| OWASP Top 10 for LLM Applications | **2025 v2.0** (LLM01 Prompt Injection … LLM10 Unbounded Consumption) + 2026 edition tracked | AI Security Engine rule taxonomy | genai.owasp.org |
| OWASP Agentic AI guidance | Agentic AI Top 10 (Dec 2025) | Agent security controls (Part 6 of spec) | genai.owasp.org |
| NIST AI RMF | 1.0 (Jan 2023) | Governance framing for the learning/feedback system (Part 15) | — |
| NIST AI 600-1 | Generative AI Profile (July 2024) | Generative-AI risk profile for assistant/agent features | — |
| CIS Critical Security Controls | v8.1 | Safeguard mapping in detection coverage reporting | cisecurity.org |
| CIS Benchmarks | current per-product | Hardening guidance for deployment docs | Deferred to Phase 7 |
| STIX | 2.1 | Indicator serialization for import/export | OASIS |
| TAXII | 2.1 | Feed collection protocol | OASIS |
| OCSF | **1.5.0** | Normalized event schema basis | ocsf.io |
| Sigma | current spec | Detection rule import format (Phase 2 converter) | sigmahq.io |
| YARA | 4.x | File scanning integration (Phase 2 malware engine) | virustotal/yara |
| CVE / CWE / CVSS | CVE Program feeds; CVSS v4.0 | Vulnerability intel (Phase 2 intel engine) | cve.org, first.org |
| OpenTelemetry | OTLP/logs & traces | Internal observability export (optional) | Phase 7 |
| Zero Trust Architecture | NIST SP 800-207 | Policy model for response engine & agent permissions | — |

## Adoption rules

1. Every alert, incident and detection rule carries machine-readable mappings
   (ATT&CK technique IDs; ATLAS where AI-related; OCSF class where event-related).
2. Mappings are generated from the in-repo taxonomy snapshot
   (`backend/detection/taxonomies/`) with a recorded `source_version` — never hard-coded strings.
3. Standards updates are re-verified at each phase gate; the table above is updated in the same
   commit that changes behavior.
