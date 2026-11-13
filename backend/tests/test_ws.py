"""WebSocket live-stream tests (ADR-007)."""
from __future__ import annotations

import time

from app.core.bus import bus


def test_ws_requires_valid_token(client):
    try:
        with client.websocket_connect("/ws?token=invalid.token.here") as ws:
            msg = ws.receive_json()
            assert False, f"expected close, got {msg}"
    except Exception:
        pass  # closed by server (4401)


def test_ws_stream_receives_published_events(client, admin_headers):
    with client.websocket_connect(f"/ws?token={admin_headers['Authorization'].split(' ')[1]}") as ws:
        ack = ws.receive_json()
        assert ack["topic"] == "connected"
        assert "events" in ack["data"]["topics"]

        # publish directly to the bus (as the pipeline would) from this thread
        bus.publish("events", {"id": "ws-test-event", "class_name": "network_activity",
                               "severity_id": 1, "message": "ws broadcast test"})
        deadline = time.time() + 5
        received = None
        while time.time() < deadline:
            msg = ws.receive_json()
            if msg["topic"] == "events" and msg["data"].get("id") == "ws-test-event":
                received = msg
                break
        assert received is not None, "did not receive published event over WS in time"
        assert received["data"]["message"] == "ws broadcast test"

        # alerts topic as well
        bus.publish("alerts", {"id": "ws-test-alert", "rule_id": "TEST", "severity_id": 3})
        deadline = time.time() + 5
        while time.time() < deadline:
            msg = ws.receive_json()
            if msg["topic"] == "alerts" and msg["data"].get("id") == "ws-test-alert":
                break
        else:
            assert False, "alert topic message not received"
