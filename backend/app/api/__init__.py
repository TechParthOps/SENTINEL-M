"""SENTINEL-M API routers."""
from app.api import auth, assets, events, alerts, incidents, rules, stats, system, ws

__all__ = ["auth", "assets", "events", "alerts", "incidents", "rules", "stats", "system", "ws"]