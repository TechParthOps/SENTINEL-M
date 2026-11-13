"""Correlation engine tests: grouping, chain escalation, incident API."""
from __future__ import annotations

from tests.conftest import ingest


def _incidents(client, headers):
    r = client.get("/api/v1/incidents?limit=200", headers=headers)
    assert r.status_code == 200
    return r.json()["incidents"]


def test_attack_chain_creates_escalated_incident(client, admin_headers):
    # Stage 1: suspicious powershell (T1059.001) on a unique host
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "chain-host-01", "process_name": "powershell.exe",
                                            "command_line": "powershell.exe -encodedcommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMA0AA="}}])
    # Stage 2: scheduled-task persistence (T1053.005) on the same host
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "chain-host-01", "process_name": "schtasks.exe",
                                            "command_line": "schtasks.exe /create /tn WinUpdate /sc onlogon /tr powershell.exe -file C:\\Temp\\ps.ps1"}}])
    incidents = [i for i in _incidents(client, admin_headers) if "chain-host-01" in i["entity_keys"]]
    assert len(incidents) == 1, "alerts on the same host must correlate into one incident"
    inc = incidents[0]
    assert inc["attack_chain"] is True
    assert inc["category"] == "potential_intrusion"
    assert set(["T1059.001", "T1053.005"]) <= set(inc["attack_ids"])
    assert inc["severity_id"] == 5  # escalated from max(alert)=4
    assert len(inc["alert_ids"]) == 2
    assert len(inc["timeline"]) == 2
    assert "chain-host-01" in inc["summary"]
    # detail endpoint returns full evidence view
    r = client.get(f"/api/v1/incidents/{inc['id']}", headers=admin_headers)
    assert r.status_code == 200
    detail = r.json()
    assert len(detail["alerts"]) == 2
    assert all(len(a["evidence_event_ids"]) >= 1 for a in detail["alerts"])


def test_separate_hosts_separate_incidents(client, admin_headers):
    cmd = "powershell.exe -encodedcommand QgBlAG4AaWduAEwAbwBvAGsA"
    for host in ("solo-host-a", "solo-host-b"):
        ingest(client, admin_headers,
               [{"type": "process", "payload": {"host": host, "process_name": "powershell.exe",
                                                "command_line": cmd + host[-1]}}])
    a = [i for i in _incidents(client, admin_headers) if "solo-host-a" in i["entity_keys"]]
    b = [i for i in _incidents(client, admin_headers) if "solo-host-b" in i["entity_keys"]]
    assert len(a) == 1 and len(b) == 1 and a[0]["id"] != b[0]["id"]
    assert a[0]["attack_chain"] is False  # single technique = not a chain


def test_incident_status_workflow(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "wf-host-01", "process_name": "powershell.exe",
                                            "command_line": "powershell.exe -encodedcommand VwBvAHIAawBmAGwAbwB3AA=="}}])
    inc = next(i for i in _incidents(client, admin_headers) if "wf-host-01" in i["entity_keys"])
    r = client.patch(f"/api/v1/incidents/{inc['id']}", headers=admin_headers,
                     json={"status": "investigating", "analyst_notes": "Looking at parent process."})
    assert r.status_code == 200
    assert r.json()["status"] == "investigating"
    assert "parent process" in r.json()["analyst_notes"]


def test_alert_ack_requires_analyst(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ack-host-01", "process_name": "powershell.exe",
                                            "command_line": "powershell.exe -encodedcommand QQBjAGsAVABlAHMAdAA="}}])
    r = client.get("/api/v1/alerts?limit=50", headers=admin_headers)
    alert = next(a for a in r.json()["alerts"] if a["entity_key"] == "ack-host-01")
    ok = client.patch(f"/api/v1/alerts/{alert['id']}", headers=admin_headers, json={"status": "ack"})
    assert ok.status_code == 200 and ok.json()["status"] == "ack"

    # viewer must be rejected
    client.post("/api/v1/auth/users",
                json={"username": "ack-viewer", "password": "Viewer!Pass12", "role": "viewer"})
    vtok = client.post("/api/v1/auth/login",
                       json={"username": "ack-viewer", "password": "Viewer!Pass12"}).json()["access_token"]
    denied = client.patch(f"/api/v1/alerts/{alert['id']}",
                          headers={"Authorization": f"Bearer {vtok}"}, json={"status": "closed"})
    assert denied.status_code == 403
