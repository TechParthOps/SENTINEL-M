# SENTINEL-M — Threat Coverage Matrix

**Last verified:** 2026-11-12
**Status legend:** ✅ implemented & tested · 🟡 partially implemented · 📋 planned (this phase roadmap) · 🚫 blocked (hardware/external) · ❌ not supported

This matrix is the single source of truth for "what does SENTINEL-M actually detect".
The UI capability-status page renders from this file's structured twin
(`backend/detection/coverage.json`) — never from marketing copy.

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
| Multi-stage attack correlation → incidents | Correlation engine | Alerts | tactics chain | ✅ |

## Phase 2 (traditional defense expansion)

| Threat | Engine | Telemetry source | ATT&CK | Status |
|---|---|---|---|---|
| C2 beaconing (periodic + jitter) | Network | Zeek/Suricata/flows | T1071 | 📋 |
| Lateral movement (SMB/RDP/WMI) | Network+Endpoint | Zeek, Sysmon | T1021 | 📋 |
| Data exfiltration volume anomalies | Network | flows | T1041 | 📋 |
| Process injection indicators | Endpoint | Sysmon | T1055 | 📋 |
| Registry/Run-key persistence | Endpoint | Sysmon | T1547.001 | 📋 |
| Credential dumping indicators | Endpoint | Sysmon/osquery | T1003 | 📋 |
| Malware static analysis (hash/YARA/entropy) | Malware engine | file pipeline | — | 📋 |
| Threat intel IOC correlation | Intelligence engine | MISP/TAXII feeds | — | 📋 |
| Identity: impossible travel, MFA fatigue | Identity engine | IdP logs | T1078 | 📋 |
| Web: XSS, SSRF, path traversal, cred stuffing | App/API engine | reverse proxy/WAF logs | T1190 | 📋 |

## Phase 3 (AI & multimodal)

| Threat | Engine | Status |
|---|---|---|
| Direct/indirect prompt injection | AI Security Engine | 📋 |
| Jailbreak / system-prompt extraction | AI Security Engine | 📋 |
| RAG poisoning indicators | AI Security Engine | 📋 |
| Agent tool abuse / excessive agency | Agent security layer | 📋 |
| Phishing / BEC text analysis | Multimodal (text) | 📋 |
| QR-code phishing | Multimodal (vision) | 📋 |
| Document manipulation indicators | Multimodal (vision) | 📋 |
| Synthetic speech indicators | Multimodal (audio) | 📋 |
| Deepfake video indicators | Multimodal (video) | 📋 |

## Phase 4–5

| Capability | Status |
|---|---|
| Autonomous investigation agents (orchestrated) | 📋 |
| Attack-path / campaign correlation | 📋 |
| Controlled response with policy + approval | 📋 |
| Deception / honeypot subsystem | 📋 |

## Explicit non-goals / limitations

- SENTINEL-M does **not** replace a full WAF, EDR kernel sensor, or vulnerability scanner in its
  early phases; log/telemetry-based detection is labeled as such in the UI.
- Deepfake detection outputs are probabilistic risk indicators, never identity verdicts.
- No offensive capability (no active exploitation, no "hacking back").
