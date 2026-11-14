# SENTINEL-M API Reference - Phase 1

Base: `/api/v1` · Auth: `Authorization: Bearer <JWT>` · Interactive docs: `/docs` (dev server).

## Conventions

- Timestamps: ISO-8601 UTC.
- Severity uses the OCSF `severity_id` scale: 0 unknown · 1 informational · 2 low · 3 medium ·
  4 high · 5 critical · 6 fatal.
- Error responses: FastAPI standard `{"detail": "..."}` with HTTP status (401, 403, 404, 409, 422, 429).
- List endpoints return `{total, ...items}` shapes; single-item endpoints return the object.

## Authentication

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/auth/login` | public (rate-limited) | `{username, password}` -> `{access_token, username, role, expires_in}` |
| GET | `/auth/me` | any | current user |
| POST | `/auth/change-password` | any | `{current_password, new_password}` (policy-enforced) |
| GET | `/auth/users` | admin | list users |
| POST | `/auth/users` | admin (or self-registration for viewer/analyst if enabled) | 409 on duplicate |

## Events

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/events/ingest` | any authenticated | body `{source:{product,version}, events:[{type,payload,time?}]}`; batch 1-1000; returns `{accepted, event_ids, alerts_created, incidents_touched}` |
| GET | `/events` | any | filters: `limit, class_name, host, src_ip, search`; newest first |

Event types: `auth`, `process`, `network`, `dns`, `file`, `http`, anything else (`generic`).
Normalization extracts observables (ipv4/domain/url) and auto-registers the host asset.

## Alerts

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/alerts` | any | filters: `limit, status, severity_gte` |
| GET | `/alerts/{id}` | any | |
| PATCH | `/alerts/{id}` | analyst+ | `{status: new\|ack\|investigating\|resolved\|closed\|false_positive}` |

Alert fields include `rule_id`, `attack_ids` (MITRE ATT&CK), `entity_key`, `evidence_event_ids`.

## Incidents

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/incidents` | any | filters: `limit, status, severity_gte` |
| GET | `/incidents/{id}` | any | detail embeds all linked alerts with evidence IDs |
| PATCH | `/incidents/{id}` | analyst+ | `{status: open\|investigating\|contained\|resolved\|closed, analyst_notes}` |

Incident fields: `attack_chain` (≥2 distinct techniques), `entity_keys`, `attack_ids`,
`timeline` (per-alert entries with evidence counts), `summary` (evidence-linked narrative).

## Detection rules

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/rules` | any | loaded JSON rules with trigger parameters + ATT&CK mappings |
| GET | `/rules/{id}` | any | |

## Assets

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/assets` | any | filters: `limit, auto_only, sample` |
| POST | `/assets` | analyst+ | manual registration; 409 on duplicate |
| GET | `/assets/{id}` | any | asset + event/alert counts |

`auto_registered` = discovered from telemetry; `sample` = seeded demo inventory (labeled in UI).

## Stats & system

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/stats/overview` | any | totals, 30-minute event timeline, class distribution, top rules 24h, intel posture |
| GET | `/health` | any | per-module status |
| GET | `/system/info` | any | version, environment, module list |
| GET | `/audit` | admin | hash-chain verification result + recent entries |
| GET | `/coverage` | any | phase/capability status + runtime truth |

## Identity (Phase 2)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/identity/summary` | any | 24h auth posture: successes/failures, distinct users, geo-change signals, identity alerts |

## AI security (Phase 3)

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/aisec/analyze-text` | analyst+ | `{text, context, label}` -> findings with heuristic confidence (OWASP LLM / MITRE ATLAS refs) |
| GET | `/aisec/analyses` | any | stored analysis records (text itself is not retained) |
| GET | `/aisec/analyses/{id}` | any | one record |

## Multimodal forensics (Phase 3)

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/media/analyze` | analyst+ | `{filename, content_base64}` -> kind-routed analysis (image/audio/video/document); bytes never stored |
| GET | `/media/analyses` | any | stored analysis records |
| GET | `/media/analyses/{id}` | any | one record |

## Threat intelligence (Phase 2)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/intel/indicators` | any | registry with filters (type, status, source, search) |
| GET | `/intel/lookup` | any | resolve one value against active indicators |
| GET | `/intel/status` | any | feed/indicator status by source and validity |
| GET | `/intel/feeds` | any | feed files present in the offline feed directory |
| POST | `/intel/feeds/reload` | admin | re-import the feed directory |
| POST | `/intel/import` | admin | import a STIX 2.1 bundle directly (`x_source` names it) |

## Autonomous investigations (Phase 4)

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/agents/investigations` | analyst+ | `{subject_type: alert|entity, subject_id}` -> deterministic 5-specialist investigation (read-only) |
| GET | `/agents/investigations` | any | list, newest first (`limit` ≤ 200) |
| GET | `/agents/investigations/{id}` | any | detail incl. per-agent task outputs |
| GET | `/agents/investigations/{id}/evidence` | any | SHA-256 evidence chain of custody |

## Threat hunting (Phase 4)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/hunt` | analyst+ | `q` (free-text/IOC), `class_name`, `host`, `hours` (default 168), `limit` -> matched events + alerts |

## Response engine (Phase 5)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/response/policy` | any | allowlisted action types, autonomy levels, emergency-stop state |
| POST | `/response/actions` | analyst+ | `{action_type, target_type, target, reason, dry_run}` -> 422 on non-allowlisted types |
| POST | `/response/actions/{id}/approve` | admin | approve a requested action |
| POST | `/response/actions/{id}/deny` | analyst+ | deny with reason |
| POST | `/response/actions/{id}/execute` | admin | execute an approved action (verification recorded) |
| POST | `/response/actions/{id}/rollback` | admin | revert a completed action where supported |
| POST | `/response/actions/{id}/verify` | analyst+ | re-check expected post-action state |
| GET | `/response/actions` | any | action history with status/verification |
| GET | `/response/denylist` | any | current denylist entries (action, target, source action id) |

## Deception lab (Phase 5)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/deception/pots` | any | honeypots (id, name, port, status, canary path, interaction count) |
| POST | `/deception/pots` | admin | create a honeypot (random decoy credentials, unprivileged port) |
| POST | `/deception/pots/{id}/start` | admin | start listener (binds `SENTINEL_DECEPTION_BIND`, default 127.0.0.1) |
| POST | `/deception/pots/{id}/stop` | admin | stop listener safely |
| GET | `/deception/pots/{id}/interactions` | any | captured interaction records |
| GET | `/deception/canary/{path}` | any | canary-token hit endpoint (records the hit; returns a decoy notice) |

## 3D virtual office (Phase 6)

No dedicated endpoints - the office renders **existing** REST contracts
(`/stats/overview`, `/agents/investigations`, `/deception/pots`, `/aisec/analyses`,
`/media/analyses`, `/health`, `/alerts`) and the live WS stream. Nothing is served by
the office page that is not a real backend fact.

## Multi-factor authentication (Phase 7)

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/auth/mfa/status` | any | `{enabled, pending_enrollment, enrolled_at, recovery_codes_remaining}` |
| POST | `/auth/mfa/setup` | any (self) | generates TOTP secret + provisioning URI + 5 one-time recovery codes; MFA stays **disabled** until activation |
| POST | `/auth/mfa/activate` | any (self) | `{code}` - first valid TOTP code activates MFA |
| POST | `/auth/mfa/verify` | anon (step-up token) | `{mfa_token, code}` - exchanges a step-up token + TOTP for a full session token |
| POST | `/auth/mfa/recovery-login` | anon (step-up token) | `{mfa_token, recovery_code}` - single-use recovery code -> full session token |
| POST | `/auth/mfa/disable` | any (self) | `{password, code}` - both required; revokes secret + recovery codes |

Login behavior: with MFA enabled, `POST /auth/login` returns `mfa_required: true` and a
**step-up token** (JWT, `scope: "mfa"`, 5-minute TTL). Step-up tokens are rejected by every
normal endpoint (401) - they only work at `/auth/mfa/verify` / `/auth/mfa/recovery-login`.

## Malware analysis (Phase 2)

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/malware/analyze` | analyst+ | static analysis: hashes, entropy, PE, strings, archives, macros |
| GET | `/malware/samples` | analyst+ | prior analysis records (hash-only evidence; bytes not retained) |

## WebSocket

`ws://<host>/ws?token=<JWT>` -> server sends `{"topic":"connected","data":{topics,user,role}}`,
then frames `{"topic":"events|alerts|incidents|assets|health|agents|response|deception","data":…}`.
Socket auth failure closes with code **4401**. The stream is a live feed; REST remains the
source of truth for state.

## Response schemas (abbreviated)

```jsonc
// GET /alerts -> one item
{
  "id": "…", "time": "2026-11-13T21:00:00", "rule_id": "AUTH-BRUTEFORCE-001",
  "rule_title": "…", "category": "credential_attack", "severity_id": 4,
  "entity_key": "203.0.113.66", "attack_ids": ["T1110"], "status": "new",
  "evidence_event_ids": ["<uuid>", "…"], "incident_id": "…"
}
```