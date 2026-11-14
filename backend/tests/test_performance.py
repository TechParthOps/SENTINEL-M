"""Performance smoke (Phase 7).

NOT a benchmark: thresholds are machine-dependent and deliberately generous for CI
machines. What this test guards is *regressions* — a sudden order-of-magnitude slowdown
(synchronous blocking calls in the hot path, accidental N+1 queries) — and the fact that
bounded batch ingestion stays bounded.
"""
from __future__ import annotations

import time

from tests.conftest import admin_headers, client


def test_bulk_ingest_stays_bounded(client, admin_headers):
    c = client
    h = admin_headers
    events = [{"type": "auth",
               "payload": {"src_ip": f"10.99.0.{i % 250}", "user": f"u{i}",
                           "outcome": "failure", "host": "perf-host"}}
              for i in range(500)]
    body = {"source": {"product": "perf-smoke", "version": "1.0.0"}, "events": events}

    start = time.perf_counter()
    r = c.post("/api/v1/events/ingest", json=body, headers=h)
    elapsed = time.perf_counter() - start

    assert r.status_code == 200, r.text
    accepted = r.json()["accepted"]
    assert accepted >= 400, f"expected most of the 500 events accepted, got {accepted}"

    # generous bound: CI machines run this in well under 5s; the guard is at 30s
    assert elapsed < 30.0, f"ingest of 500 events took {elapsed:.1f}s — hot-path regression?"


def test_detection_over_mixed_batch_completes(client, admin_headers):
    """Cooldown keys keep per-rule alerting bounded on a repeated batch."""
    c = client
    h = admin_headers
    events = [{"type": "process",
               "payload": {"host": "perf-ws", "process_name": "powershell.exe",
                           "command_line": "powershell.exe -enc ZQBmAGkAbgBlAGQA="}}
              for _ in range(50)]
    body = {"source": {"product": "perf-smoke", "version": "1.0.0"}, "events": events}

    start = time.perf_counter()
    r = c.post("/api/v1/events/ingest", json=body, headers=h)
    elapsed = time.perf_counter() - start

    assert r.status_code == 200, r.text
    assert elapsed < 20.0, f"50 repeated events took {elapsed:.1f}s — rule loop regression?"