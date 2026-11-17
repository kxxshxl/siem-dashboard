from datetime import datetime, timedelta, timezone


def test_auth_required(client):
    assert client.get("/api/events").status_code == 401
    assert client.get("/api/alerts", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_login_and_second_user_is_analyst(client, admin_headers):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong-password"})
    assert r.status_code == 401
    r = client.post("/api/auth/register", json={"username": "analyst1", "password": "password123"})
    assert r.status_code == 201 and r.json()["user"]["role"] == "analyst"
    analyst = {"Authorization": f"Bearer {r.json()['access_token']}"}
    # analysts cannot manage rules
    r = client.post("/api/rules", headers=analyst, json={
        "slug": "x-rule", "name": "X rule", "kind": "match",
        "definition": {"where": {"action": "x"}},
    })
    assert r.status_code == 403


def test_builtin_rules_seeded(client, admin_headers):
    rules = client.get("/api/rules", headers=admin_headers).json()
    slugs = {r["slug"] for r in rules}
    assert {"ssh-brute-force", "port-scan", "mass-file-encryption"} <= slugs


def test_raw_ingest_creates_and_dedupes_alert(client, admin_headers):
    base = datetime.now(timezone.utc) - timedelta(minutes=10)
    lines = "\n".join(
        f"{(base + timedelta(seconds=i)).isoformat()} web-01 sshd[1]: Failed password for root "
        f"from 198.51.100.77 port {40000 + i} ssh2"
        for i in range(12)
    )
    # ingest-token auth (no user JWT) is accepted for shippers
    r = client.post("/api/events/raw", json={"text": lines},
                    headers={"X-Ingest-Token": "test-ingest-token"})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["accepted"] == 12 and body["parsers"] == {"syslog": 12}
    assert body["alerts_created"] == 1  # second threshold crossing merged into the same alert

    alerts = client.get("/api/alerts", params={"q": "198.51.100.77"}, headers=admin_headers).json()
    assert alerts["total"] == 1
    alert = alerts["items"][0]
    assert alert["hit_count"] == 2 and alert["event_count"] == 12
    assert alert["mitre_technique"] == "T1110.001"


def test_alert_lifecycle(client, admin_headers):
    alert_id = client.get("/api/alerts", headers=admin_headers).json()["items"][0]["id"]
    r = client.patch(f"/api/alerts/{alert_id}", headers=admin_headers,
                     json={"status": "in_progress", "note": "Looking into it"})
    assert r.status_code == 200
    detail = r.json()
    assert detail["status"] == "in_progress" and detail["assignee"] == "admin"
    assert len(detail["notes"]) == 2 and detail["events"]
    r = client.post("/api/alerts/bulk", headers=admin_headers,
                    json={"ids": [alert_id], "status": "resolved"})
    assert r.json() == {"updated": 1}


def test_bad_rule_rejected_and_good_rule_backtested(client, admin_headers):
    r = client.post("/api/rules", headers=admin_headers, json={
        "slug": "broken", "name": "Broken rule", "kind": "threshold",
        "definition": {"where": {"action": "x"}, "count": 3},
    })
    assert r.status_code == 422

    definition = {"where": {"action": "login_failure"}, "group_by": ["src_ip"],
                  "count": 10, "window_seconds": 3600}
    r = client.post("/api/rules/test", headers=admin_headers,
                    json={"kind": "threshold", "definition": definition,
                          "lookback_minutes": 60 * 24 * 7})
    assert r.status_code == 200
    assert r.json()["events_scanned"] >= 12


def test_simulation_and_stats(client, admin_headers):
    r = client.post("/api/simulator/run", headers=admin_headers, json={"scenario": "ransomware"})
    assert r.status_code == 200, r.text
    assert r.json()["alerts_created"] >= 3
    assert client.post("/api/simulator/run", headers=admin_headers,
                       json={"scenario": "nope"}).status_code == 404

    stats = client.get("/api/stats/overview", params={"hours": 1}, headers=admin_headers).json()
    assert stats["totals"]["events"] > 0
    assert sum(b["events"] for b in stats["timeline"]) == stats["totals"]["events"]
    assert any(m["tactic"] == "Impact" for m in stats["mitre"])


def test_structured_ingest_folds_unknown_fields(client, admin_headers):
    r = client.post("/api/events", headers=admin_headers, json=[
        {"category": "network", "action": "connection_allowed", "src_ip": "10.0.2.20",
         "dst_ip": "203.0.113.200", "bytes_out": 99_000_000},
    ])
    assert r.status_code == 202 and r.json()["alerts_created"] == 1
    events = client.get("/api/events", params={"src_ip": "10.0.2.20"},
                        headers=admin_headers).json()
    assert events["items"][0]["extra"]["bytes_out"] == 99_000_000


def test_websocket_auth(client, admin_headers):
    import pytest
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/ws") as ws:
            ws.send_text("not-a-token")
            ws.receive_text()
    assert exc.value.code == 4401

    token = admin_headers["Authorization"].split()[1]
    with client.websocket_connect("/api/ws") as ws:
        ws.send_text(token)
        assert ws.receive_json()["type"] == "hello"
        client.post("/api/simulator/run", headers=admin_headers, json={"scenario": "port-scan"})
        kinds = {ws.receive_json()["type"] for _ in range(5)}
        assert "event" in kinds
