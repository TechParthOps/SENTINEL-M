# Detection Rules

Declarative JSON rules evaluated by the deterministic detection engine (ADR-005).

**The engine never mutates rules at runtime. No LLM participates in rule evaluation.**

## File layout

One rule per file, `<RULE-ID>.json`. The engine loads every `*.json` in this directory at
startup; a broken file is skipped with a logged error (never fatal).

## Rule schema

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `AREA-NAME-NNN` (e.g. `AUTH-BRUTEFORCE-001`) |
| `title` | yes | Human-readable rule name (shown in UI) |
| `type` | yes | `threshold` or `pattern` |
| `class` | no | Normalized event class filter (e.g. `process_activity`) |
| `where` | no | Exact field matches on the event view (threshold rules) |
| `group_by` | threshold | Field whose distinct values are counted (e.g. `src_ip`) |
| `window_seconds` | threshold | Sliding window size |
| `min_count` | threshold | Events (or distinct `distinct_field` values) needed to fire |
| `distinct_field` | no | Count distinct values of this field instead of events |
| `patterns` | pattern | List of `{field, regex}` — ALL must match |
| `entity_field` | pattern | Field whose value becomes the alert entity |
| `signature_field` | pattern | Field hashed for dedup suppression |
| `cooldown_seconds` | yes | Minimum gap between alerts for the same entity/signature |
| `severity_id` | yes | OCSF severity 0–6 |
| `attack_ids` | yes | MITRE ATT&CK technique IDs — **mandatory** |
| `attack_tactics` | recommended | ATT&CK tactic names |
| `message_template` | recommended | Alert message with `{entity}`, `{count}`, `{match}`, … |
| `status` | recommended | `stable` \| `experimental` \| `deprecated` |
| `notes` | recommended | Scope and known limitations of this rule |

## Current rules

| ID | Technique(s) | Type | Severity |
|---|---|---|---|
| AUTH-BRUTEFORCE-001 | T1110 | threshold | 4 |
| AUTH-PASSWORDSPRAY-002 | T1110.003 | threshold (distinct users) | 4 |
| AUTH-SUSPICIOUS-LOGON-003 | T1087.001 | pattern | 2 |
| NET-PORTSCAN-001 | T1046 | threshold (distinct ports) | 3 |
| HOST-PS-ATTACK-001 | T1059.001 | pattern | 4 |
| HOST-PERSIST-001 | T1053.005 | pattern | 4 |
| NET-DNSTUNNEL-001 | T1071.004 | pattern | 3 |
| FILE-RANSOM-001 | T1486 | threshold | 5 |
| WEB-SQLI-001 | T1190 | pattern | 4 |