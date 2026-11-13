"""Ingestion + normalization pipeline tests."""
from __future__ import annotations

from tests.conftest import ingest


def test_ingest_requires_auth(client):
    r = client.post("/api/v1/events/ingest",
                    json={"source": {"product": "x"}, "events": [{"type": "auth", "payload": {}}]})
    assert r.status_code == 401


def test_ingest_mixed_batch_and_query(client, admin_headers):
    events = [
        {"type": "auth", "payload": {"outcome": "failure", "user": "root", "src_ip": "203.0.113.50",
                                     "host": "dc-01", "message": "failed password for root"}},
        {"type": "process", "payload": {"host": "ws-eng-07", "process_name": "powershell.exe",
                                        "command_line": "powershell.exe -Command Get-Process"}},
        {"type": "network", "payload": {"src_ip": "10.20.3.31", "dst_ip": "10.10.2.10",
                                        "dst_port": 5432, "protocol": "tcp"}},
        {"type": "dns", "payload": {"host": "ws-eng-07", "src_ip": "10.20.3.31",
                                    "dns_query": "updates.microsoft.com"}},
    ]
    r = ingest(client, admin_headers, events)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["accepted"] == 4
    assert len(body["event_ids"]) == 4

    q = client.get("/api/v1/events?limit=10", headers=admin_headers)
    assert q.status_code == 200
    listed = q.json()["events"]
    assert len(listed) >= 4
    classes = {e["class_name"] for e in listed}
    assert {"authentication", "process_activity", "network_activity", "dns_activity"} <= classes


def test_ingest_unknown_type_preserved_as_generic(client, admin_headers):
    r = ingest(client, admin_headers,
               [{"type": "future-sensor-type", "payload": {"host": "ws-x", "data": "abc"}}])
    assert r.status_code == 200
    q = client.get("/api/v1/events?class_name=generic&limit=5", headers=admin_headers)
    assert q.status_code == 200
    assert len(q.json()["events"]) >= 1  # never dropped


def test_ingest_normalizes_observables(client, admin_headers):
    r = ingest(client, admin_headers,
               [{"type": "network", "payload": {"src_ip": "198.51.100.7", "dst_ip": "10.0.0.1",
                                                "dst_port": 443, "protocol": "tcp",
                                                "message": "tls to cdn.example-cloud.net"}}])
    assert r.status_code == 200
    eid = r.json()["event_ids"][0]
    q = client.get("/api/v1/events?limit=1", headers=admin_headers)
    ev = [e for e in q.json()["events"] if e["id"] == eid][0]
    types = {o["type"] for o in ev["observables"]}
    assert "ipv4" in types and "domain" in types


def test_ingest_auto_registers_asset(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"host": "new-host-77", "src_ip": "10.1.1.77",
                                         "outcome": "success", "user": "svc-backup"}}])
    r = client.get("/api/v1/assets", headers=admin_headers)
    hostnames = [a["hostname"] for a in r.json()["assets"]]
    assert "new-host-77" in hostnames
    asset = next(a for a in r.json()["assets"] if a["hostname"] == "new-host-77")
    assert asset["auto_registered"] is True
    assert asset["sample"] is False


def test_ingest_batch_limit_enforced(client, admin_headers):
    events = [{"type": "auth", "payload": {"src_ip": f"10.9.{i // 250}.{i % 250}",
                                           "outcome": "success", "user": "u"}} for i in range(1001)]
    r = ingest(client, admin_headers, events)
    assert r.status_code == 422


def test_ingest_empty_batch_rejected(client, admin_headers):
    r = ingest(client, admin_headers, [])
    assert r.status_code == 422
