# SENTINEL-M - Threat Coverage Matrix

**Last verified:** 2026-11-14
**Status legend:** ✅ implemented & tested · 🟡 partially implemented · 📋 planned (this phase roadmap) · 🚫 blocked (hardware/external) · ❌ not supported

This matrix is the single source of truth for "what does SENTINEL-M actually detect".
The UI capability-status page renders from this file's structured twin
(`backend/app/coverage.json`) - never from marketing copy.

## Phase 1 (this phase)

| Threat | Engine | Telemetry source | ATT&CK | Status |
|---|---|---|---|---|
| SSH/auth brute force | Detection (AUTH-BRUTEFORCE-001) | Ingested auth events (syslog/agent) | T1110 | ✅ |
| Password spray | Detection (AUTH-PASSWORDSPRAY-002) | Auth events | T1110.003 | ✅ |
| Port scanning / service discovery | Detection (NET-PORTSCAN-001) | Connection events | T1046 | ✅ |
| Suspicious PowerShell (encoded/download) | Detection (HOST-PS-ATTACK-001) | Process events | T1059.001 | ✅ |
| Suspicious scheduled-task persistence | Detection (HOST-PERSIST-001) | Process/scheduling events | T1053.005 | ✅ |
| DNS tunneling indicators | Detection (NET-DNSTUNNEL-001) | DNS events | T1071.004 | ✅ |
| Ransomware-like file behavior | Detection (FILE-RANSOM-001) | File events | T1486 | ✅ |
| SQL injection indicators | Detection (WEB-SQLI-001) | HTTP request events | T1190 | ✅ |
| Multi-stage attack correlation -> incidents | Correlation engine | Alerts | tactics chain | ✅ |

## Phase 2 (traditional defense expansion)

| Threat | Engine | Telemetry source | ATT&CK | Status |
|---|---|---|---|---|
| C2 beaconing (periodic + jitter) | Detection (NET-BEACON-001) | Connection/flow events | T1071 | ✅ |
| Lateral movement (SMB/RDP/WMI) | Endpoint rules | Zeek, Sysmon | T1021 | 📋 (adapters planned) |
| Data exfiltration volume anomalies | Detection (NET-EXFIL-001) | flows | T1041 | ✅ |
| Process injection indicators | Endpoint rules (HOST-CREDDUMP-001 set) | Sysmon | T1055 | 🟡 partial (signals via Sysmon-style events; adapters planned) |
| Registry/Run-key persistence | Detection (HOST-REGISTRY-PERSIST-001) | Sysmon-style registry events | T1547.001 | ✅ |
| Credential dumping indicators | Detection (HOST-CREDDUMP-001) | Sysmon/osquery | T1003 | ✅ |
| Malware static analysis (hash/entropy/PE/macros) | Malware engine | file pipeline | - | ✅ (YARA + sandbox 📋) |
| Threat intel IOC correlation | Intelligence engine (STIX import, aging, INTEL-IOC-001) | MISP/TAXII feeds | - | ✅ (live MISP/OpenCTI clients 📋) |
| Identity: impossible travel | Identity engine + ID-IMPOSSIBLE-TRAVEL-001 | IdP logs (geo-annotated) | T1078 | ✅ |
| Identity: MFA fatigue | Identity engine | IdP logs | T1621 | 📋 |
| Web: XSS, SSRF, path traversal | Detection (WEB-XSS/SSRF/TRAVERSAL-001) | reverse proxy/WAF logs | T1190 | ✅ |

## Phase 3 (AI & multimodal)

| Threat | Engine | Status |
|---|---|---|
| Direct/indirect prompt injection | AI Security Engine (`app/aisec/`) - deterministic patterns + confidence | ✅ |
| Jailbreak / system-prompt extraction | AI Security Engine | ✅ |
| RAG poisoning indicators | AI Security Engine (instruction-like text + hidden unicode in document context) | ✅ |
| LLM data disclosure (keys/tokens/credentials) | AI Security Engine | ✅ |
| Agent tool abuse / excessive agency | AI Security Engine (tool-override text indicators) + Phase-4 read-only agent boundaries | ✅ |
| Phishing / BEC text analysis | AI Security Engine (urgency/authority/lures/link indicators) | ✅ |
| QR-code phishing | Multimodal image pipeline (OpenCV decode + payload analysis) | ✅ |
| Image metadata / synthetic-image indicators | Multimodal image pipeline (EXIF + generative-AI tool strings + recompression probe) | ✅ (heuristic, low-confidence) |
| Document manipulation indicators | Multimodal document pipeline (PDF action objects + OOXML parts) | ✅ |
| OCR | Not bundled (no tesseract binary in this build) | 🚫 blocked |
| Synthetic speech indicators | Multimodal audio pipeline (WAV/PCM statistics, low confidence) | ✅ within WAV scope |
| Deepfake video indicators | Multimodal video pipeline (frame statistics only - no neural detectors) | ✅ within heuristic scope |

## Phase 4 (autonomous investigation)

| Capability | Engine | Status |
|---|---|---|
| Investigation orchestration (alert/entity subject) | `app/agents/` orchestrator + 5 specialists (alert_triage, asset_context, intel_check, related_activity, synthesis) | ✅ deterministic, read-only |
| Verdict + summary (suspicious/malicious/benign/unknown) | synthesis specialist over corroborating evidence | ✅ |
| Evidence chain of custody per investigation | per-step SHA-256 chain, tamper-evident | ✅ |
| Threat hunting queries (IOC/entity/rule sweeps) | `/hunt` API + Hunt page UI | ✅ |
| Incident/campaign timeline correlation | correlation engine (existing) + related_activity specialist | ✅ |
| LLM-narrated summaries | optional post-hook - no model in this build | 🚫 blocked |

## Phase 5 (response & deception)

| Capability | Engine | Status |
|---|---|---|
| Policy-authorized response actions (isolate host, block IOC, disable user, quarantine file, kill process, snapshot) | `app/response/` allowlist engine | ✅ allowlist-only |
| Autonomy levels L0/L1/L2, approval queue, dry-run | response engine + `SENTINEL_RESPONSE_ENABLED` emergency stop | ✅ |
| Post-action verification + rollback | response engine (verified/reverted states recorded) | ✅ |
| Deception: honeypots with decoy credentials + canary tokens | `app/deception/` listeners (loopback default `SENTINEL_DECEPTION_BIND`), DECEPTION-HP-001 alerts | ✅ |
| Enterprise response integrations (ticketing/chatops) | none available | 🚫 blocked |

## Phase 6 (3D virtual office)

| Capability | Engine | Status |
|---|---|---|
| Interactive 3D ops floor (R3F, orbit/zoom, room selection) - realistic SOC: partitioned rooms with door gaps/glass, desks with monitors and chairs, wall signage, central video wall, ceiling beams | `components/OfficeScene.tsx` + `store/office.ts` | ✅ (2D fallback included) |
| Room activity pillars from real metrics | REST stats/agents/intel/deception/aisec/media | ✅ |
| Live event markers from confirmed WS frames | bus topics alerts/incidents/agents/response/deception | ✅ |
| Incident historical replay (real persisted alerts, pause/resume) | `/alerts` history | ✅ |
| Simulated agent avatars / attack-path animation | declined by design (ADR-008 honesty) - real WS markers shown instead | 📋 |
| Screenshots/traces of the 3D view in docs | desktop window required (unavailable in CI shell) | 🚫 blocked |

## Phase 7 - enterprise readiness (partial)

| Capability | Engine / tool | Status |
|---|---|---|
| MFA - TOTP second factor (RFC 6238, stdlib-only) | `app/core/mfa.py` + `/auth/mfa/*` | ✅ |
| MFA - single-use recovery codes (SHA-256 hashed) | `app/core/mfa.py` | ✅ |
| MFA - step-up token scope boundary | security `get_current_user` rejects `scope: "mfa"` | ✅ |
| Guided local installer + `.env` first-run config | `scripts/install.ps1` | ✅ |
| Database backup (consistent online backup + rolling retention) | `scripts/backup.py` | ✅ |
| SBOM (CycloneDX 1.5 from installed metadata) | `scripts/generate_sbom.py` -> `docs/SBOM.json` (184 components) | ✅ |
| Performance smoke (regression guards, not benchmarks) | `backend/tests/test_performance.py` | ✅ |
| Automated updates / packaged distribution | no GUI packaging in this build | 📋 |
| SSO / SAML / LDAP, ticketing/chatops integrations | external identity/workflow providers | 🚫 blocked |

## Explicit non-goals / limitations

- SENTINEL-M does **not** replace a full WAF, EDR kernel sensor, or vulnerability scanner in its
  early phases; log/telemetry-based detection is labeled as such in the UI.
- Deepfake detection outputs are probabilistic risk indicators, never identity verdicts.
- No offensive capability (no active exploitation, no "hacking back").
