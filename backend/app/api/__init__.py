"""SENTINEL-M API routers."""
from app.api import (
    aisec,
    agents,
    alerts,
    assets,
    auth,
    deception,
    events,
    hunt,
    identity,
    incidents,
    intelligence,
    malware,
    multimodal,
    response,
    rules,
    stats,
    system,
    ws,
)

__all__ = [
    "aisec", "agents", "auth", "assets", "deception", "events", "alerts", "hunt", "incidents",
    "identity", "intelligence", "malware", "multimodal", "response", "rules", "stats", "system", "ws",
]