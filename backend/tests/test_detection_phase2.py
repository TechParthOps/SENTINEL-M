"""Phase-2 detection rules + identity annotation tests."""
from __future__ import annotations

from tests.conftest import ingest


def _get_alerts(client, headers, rule_id):
    r = client.get("/api/v1/alerts?limit=200", headers=headers)
    assert r.status_code == 200
    return [a for a in r.json()["alerts"] if a["rule_id"] == rule_id]


def test_beaconing_composite_group(client, admin_headers):
    events = [{"type": "network", "payload": {"src_ip": "10.40.0.9", "dst_ip": "185.100.10.9",
                                              "dst_port": 8443, "protocol": "tcp"}}
              for _ in range(13)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "NET-BEACON-001")
    assert len(alerts) == 1
    assert "10.40.0.9→185.100.10.9→8443" == alerts[0]["entity_key"]
    assert "T1071.001" in alerts[0]["attack_ids"]


def test_dga_high_entropy_domains(client, admin_headers):
    # 40-char label, entropy 3.2+ → 'high' class
    events = [{"type": "dns", "payload": {"host": "ws-dga-01", "src_ip": "10.40.0.20",
                                          "dns_query": f"{'a' if i == 0 else 'q9z2k1m4x7'}{'b3k9z2m4x8' * i}.c2-ring-top.net"}}
              for i in range(4)]
    ingest(client, admin_headers, events)
    alerts = _get_alerts(client, admin_headers, "NET-C2-DGA-001")
    assert len(alerts) == 1
    assert "T1568.002" in alerts[0]["attack_ids"]


def test_normal_dns_never_dga(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "dns", "payload": {"host": "ws-dga-02", "dns_query": "www.github.com"}}] * 3)
    assert len(_get_alerts(client, admin_headers, "NET-C2-DGA-001")) == 0


def test_exfil_volume_threshold(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "network", "payload": {"src_ip": "10.40.0.30", "dst_ip": "45.60.70.80",
                                            "dst_port": 443, "bytes_out": 75000000}}])
    alerts = _get_alerts(client, admin_headers, "NET-EXFIL-001")
    assert len(alerts) == 1
    assert "T1041" in alerts[0]["attack_ids"]
    # below threshold: silent
    ingest(client, admin_headers,
           [{"type": "network", "payload": {"src_ip": "10.40.0.31", "dst_ip": "45.60.70.81",
                                            "dst_port": 443, "bytes_out": 1000}}])
    assert len(_get_alerts(client, admin_headers, "NET-EXFIL-001")) == 1


def test_credential_dumping(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-dump-01",
                                            "process_name": "procdump.exe",
                                            "command_line": "procdump.exe -accepteula -ma lsass.exe dump.dmp"}}])
    alerts = _get_alerts(client, admin_headers, "HOST-CREDDUMP-001")
    assert len(alerts) == 1
    assert alerts[0]["severity_id"] == 5
    assert "T1003.001" in alerts[0]["attack_ids"]


def test_registry_runkey_persistence(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-reg-01", "process_name": "reg.exe",
                                            "command_line": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Temp\\u.exe"}}])
    alerts = _get_alerts(client, admin_headers, "HOST-REGISTRY-PERSIST-001")
    assert len(alerts) == 1
    assert "T1547.001" in alerts[0]["attack_ids"]


def test_service_creation(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "process", "payload": {"host": "ws-svc-01", "process_name": "sc.exe",
                                            "command_line": "sc create WinUpdater binpath= C:\\Temp\\svc.exe start= auto"}}])
    alerts = _get_alerts(client, admin_headers, "HOST-SVC-CREATE-001")
    assert len(alerts) == 1
    assert "T1543.003" in alerts[0]["attack_ids"]


def test_web_xss(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "http", "payload": {"src_ip": "9.9.9.10", "http_method": "GET",
                                         "http_url": "/search?q=<script>alert(1)</script>", "http_status": 200}}])
    alerts = _get_alerts(client, admin_headers, "WEB-XSS-001")
    assert len(alerts) == 1


def test_web_ssrf_metadata(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "http", "payload": {"src_ip": "9.9.9.11", "http_method": "POST",
                                         "http_url": "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
                                         "http_status": 200}}])
    alerts = _get_alerts(client, admin_headers, "WEB-SSRF-001")
    assert len(alerts) == 1


def test_web_traversal(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "http", "payload": {"src_ip": "9.9.9.12", "http_method": "GET",
                                         "http_url": "/download?file=../../../../etc/passwd",
                                         "http_status": 404}}])
    alerts = _get_alerts(client, admin_headers, "WEB-TRAVERSAL-001")
    assert len(alerts) == 1


def test_impossible_travel(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"user": "ceo-user", "outcome": "success",
                                            "src_ip": "10.0.0.11", "host": "dc-01",
                                            "geo_country": "US",
                                            "message": "login accepted"}}])
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"user": "ceo-user", "outcome": "success",
                                            "src_ip": "82.100.20.30", "host": "dc-01",
                                            "geo_country": "RU",
                                            "message": "login accepted"}}])
    alerts = _get_alerts(client, admin_headers, "ID-IMPOSSIBLE-TRAVEL-001")
    assert len(alerts) == 1
    assert alerts[0]["entity_key"] == "ceo-user"
    assert "T1078" in alerts[0]["attack_ids"]


def test_same_country_logins_no_travel(client, admin_headers):
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"user": "normal-user", "outcome": "success",
                                            "src_ip": "10.0.0.12", "host": "dc-01",
                                            "geo_country": "DE"}}])
    ingest(client, admin_headers,
           [{"type": "auth", "payload": {"user": "normal-user", "outcome": "success",
                                            "src_ip": "10.0.0.13", "host": "dc-01",
                                            "geo_country": "DE"}}])
    alerts = _get_alerts(client, admin_headers, "ID-IMPOSSIBLE-TRAVEL-001")
    assert all(a["entity_key"] != "normal-user" for a in alerts)


def test_rules_count_is_nineteen(client, admin_headers):
    r = client.get("/api/v1/rules", headers=admin_headers)
    assert r.status_code == 200
    assert r.json()["total"] == 19, f"expected 19 loaded rules, got {r.json()['total']}"