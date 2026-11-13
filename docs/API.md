# SENTINEL-M API Reference — Phase 1

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
| POST | `/auth/login` | public (rate-limited) | `{username, password}` → `{access_token, username, role, expires_in}` |
| GET | `/auth/me` | any | current user |
| POST | `/auth/change-password` | any | `{current_password, new_password}` (policy-enforced) |
| GET | `/auth/users` | admin | list users |
| POST | `/auth/users` | admin (or self-registration for viewer/analyst if enabled) | 409 on duplicate |

## Events

| Method | Path | Role | Notes |
|---|---|---|---|
| POST | `/events/ingest` | any authenticated | body `{source:{product,version}, events:[{type,payload,time?}]}`; batch 1–1000; returns `{accepted, event_ids, alerts_created, incidents_touched}` |
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
| GET | `/stats/overview` | any | totals, 30-minute event timeline, class distribution, top rules 24h |
| GET | `/health` | any | per-module status |
| GET | `/system/info` | any | version, environment, module list |
| GET | `/audit` | admin | hash-chain verification result + recent entries |
| GET | `/coverage` | any | phase/capability status + runtime truth |

## WebSocket

`ws://<host>/ws?token=<JWT>` → server sends `{"topic":"connected","data":{topics,user,role}}`,
then frames `{"topic":"events|alerts|incidents|assets|health|agents","data":…}`.
Socket auth failure closes with code **4401**. The stream is a live feed; REST remains the
source of truth for state.

## Response schemas (abbreviated)

```jsonc
// GET /alerts → one item
{
  "id": "…", "time": "2026-11-13T21:00:00", "rule_id": "AUTH-BRUTEFORCE-001",
  "rule_title": "…", "category": "credential_attack", "severity_id": 4,
  "entity_key": "203.0.113.66", "attack_ids": ["T1110"], "status": "new",
  "evidence_event_ids": ["<uuid>", "…"], "incident_id": "…"
}
```