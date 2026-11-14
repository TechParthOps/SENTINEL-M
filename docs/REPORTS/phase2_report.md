# Development Report - Phase 2: Traditional Cyber Defense

**Date:** 2026-11-14 · **Milestone:** Phase 2 · **Status:** complete & verified

## What was implemented

1. **Detection rule expansion** (detection-rules/, now 18 rules): NET-BEACON-001 (beaconing with
   jitter + volume), NET-C2-DGA-001 (DNS entropy/length DGA indicators), NET-EXFIL-001 (outbound
   volume threshold), WEB-XSS-001, WEB-SSRF-001, WEB-TRAVERSAL-001, HOST-SVC-CREATE-001,
   HOST-REGISTRY-PERSIST-001, HOST-CREDDUMP-001, ID-IMPOSSIBLE-TRAVEL-001. Rule engine gained
   composite `group_by` lists, `where_gte` numeric comparisons and `_derived` view fields
   (DNS label entropy, byte volumes, NXDOMAIN, geo fields).
2. **Identity engine** (`app/identity/`): cross-session auth correlation that annotates successive
   successful logons with geo changes before detection runs; impossible-travel detection fires from
   the annotated view. Works from any auth telemetry with `user`/`outcome`/`geo_country` - no
   bundled geolocation DB (documented limitation).
3. **Malware analysis engine** (`app/malware/`): file submission -> deterministic static analysis
   (multi-hash digest, Shannon entropy, PE header parse, string extraction, archive/zip member
   scan, Office macro detection) with suspicious-signal scoring. No byte retention (hash-only
   evidence) - documented honestly.
4. **Threat intelligence engine** (`app/intelligence/`): STIX 2.1 bundle parsing, indicator
   registry (dedup by id/value), validity-based aging (active/expired/future), source metadata,
   event enrichment pipeline (observables -> IOC lookup -> INTEL-IOC-001 alerts), offline-first
   local feed directory (`intel-feeds/`) + admin API for direct bundle import and feed reload.
5. **New APIs:** `/identity/summary`, `/intel/*` (indicators, lookup, status, feeds, reload,
   import), `/malware/*` (analyze + list). Event query API now returns the raw payload view.
6. **Frontend pages:** Network Security, Endpoint Security, Identity Security, Threat Intelligence,
   Multimodal Forensics (file analysis), plus honest Planned panels for the remaining routes
   (`/multimodal` previously mis-pointed at the Malware page - fixed).

## Why

Phase 2 extends the Phase-1 pipeline to traditional defense depth: network/endpoint/web attack
surface, identity, malware triage and external intel correlation - all deterministic, offline
and test-covered before autonomous phases build on it.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest - now includes detection Phase-2 rules, intel, malware, identity | **73/73 passed** |
| `frontend`: vitest | **7/7 passed** |
| Frontend production build (`tsc -b && vite build`) | **clean, 0 errors** |

## Known limitations (documented)

1. Log-tail adapters for Zeek/Suricata/Sysmon/osquery/Wazuh are planned (schema coverage exists;
   adapters still to come).
2. YARA scanning + isolated sandbox execution are planned; current malware analysis is static and
   deterministic.
3. MISP/OpenCTI/TAXII live clients are planned; Phase 2 uses local STIX files (offline-first).
4. Impossible travel requires the sensor to attach geo fields; no bundled geolocation database.

## Remaining work (next)

**Phase 3 - AI & multimodal:** prompt-injection/jailbreak detection, RAG poisoning indicators,
phishing/BEC text analysis, QR-code security, document forensics, synthetic-speech and deepfake
risk indicators - all evidence-based with stated confidence and limitations.
