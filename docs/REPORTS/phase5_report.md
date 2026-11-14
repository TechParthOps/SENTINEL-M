# Development Report - Phase 5: Response & Deception

**Date:** 2026-11-14 · **Milestone:** Phase 5 · **Status:** complete & verified (allowlist + approval + verification + rollback; loopback isolation)

## What was implemented

1. **Response engine** (`backend/app/response/`):
   - Allowlisted action types only: `isolate_asset`, `block_ioc`, `disable_user`,
     `quarantine_file`, `kill_process`, `snapshot_host`. Anything else -> 422 `policy_denied`,
     audit-recorded.
   - Autonomy levels **L0** (manual only), **L1** (analyst request, admin approve),
     **L2** (admin request+execute). Every transition audit-logged with actor and reason.
   - Lifecycle: request -> dry-run -> approve/deny -> execute -> verify -> rollback.
     Verification re-checks expected post-action state (e.g. `assets.isolated`);
     rollback restores where the action supports it and records the outcome.
   - Emergency stop: `SENTINEL_RESPONSE_ENABLED=false` rejects all real executions.
   - `assets.isolated` column with an `ALTER TABLE` migration in `_run_migrations()` for
     pre-existing databases.
2. **Deception engine** (`backend/app/deception/`):
   - Honeypots: TCP banner listeners on unprivileged ports, bound to
     `SENTINEL_DECEPTION_BIND` (**127.0.0.1 default** - network exposure is opt-in),
     random decoy credentials per pot, canary token paths.
   - Interactions recorded; each recorded hit produces a `DECEPTION-HP-001` alert
     (critical) via the normal detection path plus `deception.*` WS events.
   - Safe shutdown: `stop_all()` in lifespan; listeners never bind production data paths.
3. **Frontend**: Response page (policy view, request/dry-run/approve/execute/rollback/verify,
   action history, denylist) and Deception page (pot CRUD, start/stop, interaction feed).

## Why

Phase 5 is where automation becomes dangerous, so it is gated three ways: policy allowlist,
explicit approval, and verified reversible effects - with a global kill switch.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest (adds `test_response.py`, `test_deception.py`) | **110/110 passed** |
| `frontend`: vitest / `tsc -b` / build | **7/7 passed**; type-check clean; build clean |
| Live HTTP smoke (real uvicorn): POST response action -> denied non-allowlist; allowlisted dry-run; deception pot create/start/stop; interactions recorded | passed |

## Honest limitations

- Executors simulate effect for network-level actions against local state (there is no
  real EDR/firewall integration) - the engine records verification against the DB state
  it actually changed; no external system is contacted.
- Honeypots bind loopback by default; binding to a routable address requires deliberate
  operator configuration and is not recommended in this build.
- No ticketing/chatops integrations exist in this build (`blocked` in coverage).