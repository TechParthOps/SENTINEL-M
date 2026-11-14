# Development Report - Phase 4: Autonomous Investigation

**Date:** 2026-11-14 · **Milestone:** Phase 4 · **Status:** complete & verified (deterministic, read-only scope)

## What was implemented

1. **Agent orchestrator** (`backend/app/agents/`): deterministic pipeline, no LLM required:
   - Specialists: `alert_triage` (subject lookup + rule context), `asset_context` (entity
     asset ownership, isolation state), `intel_check` (IOC correlation against active
     indicators), `related_activity` (7-day correlated alerts/incidents), `synthesis`
     (verdict: malicious / suspicious / benign / unknown + human-readable reasons).
   - Every step writes a per-task evidence record; the investigation carries a SHA-256
     hash chain (`record_hash` links to `prev_hash`) displayed verifiably in the UI.
   - 10-second soft time budget with a recorded `budget_exceeded` marker; failures are
     recorded per agent, never swallowed silently.
2. **Read-only by construction**: agents receive a DB session and no response-engine access;
   there is no code path from an agent to a state-changing action (ADR boundary, asserted
   by tests).
3. **Threat hunting** (`backend/app/api/hunt.py`): read-only sweeps over retained events +
   alerts by free-text/IOC value, event class, host and time window (≤ 90 days). JSON
   observable matching runs after a bounded SQL pre-filter - a documented performance
   trade-off for the local-first single-node deployment.
4. **Frontend**: Agents page (start investigation, task timeline, evidence chain with
   verification) and Hunt page.

## Why

Agents must be trustworthy before they are powerful: the phase delivers investigation
automation with verifiable evidence handling while response authority stays in Phase 5's
approval workflow.

## Tests executed & results

| Suite | Result |
|---|---|
| `backend`: pytest (adds `test_agents.py`) | **110/110 passed** |
| `frontend`: vitest / `tsc -b` / build | **7/7 passed**; type-check clean; build clean |
| Live HTTP smoke (real uvicorn): investigation on an alert -> completed, verdict `suspicious`, evidence chain verifiable | passed |

## Honest limitations

- No LLM narration/planning in this build (optional post-hook, no model shipped) - flagged
  `blocked` in coverage.
- Specialists are deterministic rules over retained data; "autonomous" means orchestrated
  and evidence-backed, not self-improving.
- Hunting filters retained telemetry only; no live sensor querying.