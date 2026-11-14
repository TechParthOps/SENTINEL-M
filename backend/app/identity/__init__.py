"""Identity threat engine (Phase 2).

Phase 2 responsibility: annotate authentication events with cross-session context that
static single-event rules cannot see — currently successive-login geography change
(impossible travel). Later: MFA fatigue, dormant-account activity, token anomalies.
"""