"""Authenticated WebSocket live stream (ADR-007).

Connect: ws://host/ws?token=<JWT>. Messages: {"topic": ..., "data": ...}.
Subscribing to the bus wildcard topic receives every published topic exactly once.
State remains authoritative from REST endpoints; the stream is a live feed, not a database.
"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.bus import bus
from app.core.database import SessionLocal
from app.core.security import TokenError, decode_jwt
from app.models.user import User

router = APIRouter()


@router.websocket("/ws")
async def ws_stream(ws: WebSocket):
    token = ws.query_params.get("token", "")
    try:
        claims = decode_jwt(token)
    except TokenError:
        await ws.close(code=4401, reason="invalid token")
        return
    db = SessionLocal()
    try:
        user = db.get(User, claims.get("sub"))
        if user is None or not user.is_active:
            await ws.close(code=4401, reason="user not valid")
            return
        username = user.username
        role = user.role
    finally:
        db.close()

    await ws.accept()
    await ws.send_json(
        {
            "topic": "connected",
            "data": {"topics": bus.topics + ["*"], "user": username, "role": role},
        }
    )
    q = bus.subscribe("*")
    try:
        while True:
            msg = await q.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        try:
            bus.unsubscribe("*", q)
        except Exception:
            pass