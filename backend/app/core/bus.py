"""In-process async event bus with WebSocket fanout (ADR-007).

Safe to call `publish` from any thread: if called from outside the event loop
thread, delivery is scheduled via `call_soon_threadsafe`.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict

_TOPICS = ["events", "alerts", "incidents", "assets", "health", "agents", "response", "deception"]


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._published: dict[str, int] = defaultdict(int)

    # -- lifecycle ---------------------------------------------------------
    def set_loop(self, loop: asyncio.AbstractEventLoop | None) -> None:
        self._loop = loop

    @property
    def loop_running(self) -> bool:
        return self._loop is not None and self._loop.is_running()

    # -- subscriptions -----------------------------------------------------
    def subscribe(self, topic: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers[topic].add(q)
        return q

    def unsubscribe(self, topic: str, q: asyncio.Queue) -> None:
        self._subscribers[topic].discard(q)

    @property
    def subscriber_count(self) -> int:
        return sum(len(v) for v in self._subscribers.values())

    @property
    def topics(self) -> list[str]:
        return list(_TOPICS)

    # -- publishing --------------------------------------------------------
    def publish(self, topic: str, data) -> int:
        self._published[topic] += 1
        targets: set = set(self._subscribers.get(topic, set())) | set(
            self._subscribers.get("*", set())
        )
        delivered = 0
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        for q in targets:
            try:
                self._deliver(q, topic, data, running)
                delivered += 1
            except Exception:  # never break the pipeline for a dead subscriber
                continue
        return delivered

    def _deliver(self, q: asyncio.Queue, topic: str, data, running) -> None:
        msg = {"topic": topic, "data": data}
        if self.loop_running and running is self._loop:
            q.put_nowait(msg)
        elif self.loop_running:
            self._loop.call_soon_threadsafe(q.put_nowait, msg)
        else:  # no loop (tests / sync context): buffer in queue directly
            q.put_nowait(msg)

    def stats(self) -> dict:
        return {"subscribers": self.subscriber_count, "published": dict(self._published)}


bus = EventBus()