# Security Policy

## Supported / responsible use

SENTINEL-M is **defensive security software**. It contains no offensive capability and must not
be used to attack systems you do not own or are not authorized to defend. The deception subsystem
(Phase 5) operates only on explicitly configured, isolated decoys.

## Reporting a vulnerability

Do **not** open a public issue for security defects.

1. Email: `security@sentinel-m.local` (placeholder until project infrastructure exists)
2. Include: affected version/commit, reproduction steps, impact assessment.
3. We aim to acknowledge within 5 business days and publish fixes with the next patch release.

## Security model summary (Phase 1)

- Authentication: JWT (HS256) bearer tokens; PBKDF2-SHA256 (600k iterations) password hashing.
- Authorization: role-based (`admin`, `analyst`, `viewer`); enforced per route.
- All state-changing API calls are recorded in the tamper-evident-intent audit log (hash-chained).
- Ingestion endpoint is authenticated and rate-limited; inputs are strictly validated (Pydantic).
- Secrets: never in source. `.env` is git-ignored; `SECRET_KEY` must be set by the operator.
- Data: SQLite in WAL mode with filesystem ACL responsibility on the operator (local-first).
- Evidence integrity (hash-chained audit, evidence hashing) extends in Phases 2–5.

## Known Phase 1 limitations (documented honestly)

- Single-node deployment; no HA.
- MFA is planned (Phase 7), not present.
- Audit log is append-only within SQLite; external WORM offload is Phase 7.
- WebSocket auth uses the same JWT; no per-socket scope separation yet.
