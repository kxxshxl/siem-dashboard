from app.ingest.parsers import parse_line
from app.schemas import EventIn


def test_sshd_failed_password():
    name, e = parse_line(
        "Nov 18 10:15:01 web-01 sshd[1234]: Failed password for invalid user admin "
        "from 203.0.113.5 port 52814 ssh2"
    )
    assert name == "syslog"
    assert e["action"] == "login_failure"
    assert e["username"] == "admin" and e["src_ip"] == "203.0.113.5" and e["host"] == "web-01"
    EventIn(**e)  # must validate


def test_sshd_accepted_iso_timestamp():
    name, e = parse_line(
        "2026-11-18T10:15:01.123+00:00 web-01 sshd[99]: Accepted publickey for deploy "
        "from 10.0.5.21 port 50000 ssh2"
    )
    assert name == "syslog" and e["action"] == "login_success" and e["username"] == "deploy"
    assert e["timestamp"].tzinfo is None


def test_ufw_block():
    _, e = parse_line(
        "Nov 18 10:16:00 gw kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.7 DST=10.0.1.10 "
        "LEN=44 PROTO=TCP SPT=41234 DPT=3389 WINDOW=1024 SYN"
    )
    assert e["category"] == "network" and e["action"] == "connection_blocked"
    assert e["dst_port"] == 3389 and e["src_ip"] == "198.51.100.7"


def test_sudo():
    _, e = parse_line(
        "Nov 18 10:17:00 web-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
        "COMMAND=/usr/bin/systemctl restart nginx"
    )
    assert e["action"] == "sudo" and e["username"] == "alice"
    assert e["extra"]["process"]["cmdline"] == "/usr/bin/systemctl restart nginx"


def test_access_log():
    name, e = parse_line(
        '203.0.113.50 - - [18/Nov/2026:10:00:00 +0000] "GET /products.php?id=1%20UNION%20SELECT'
        '%201 HTTP/1.1" 500 120 "-" "sqlmap/1.8"'
    )
    assert name == "access_log"
    assert e["extra"]["http"]["status"] == 500
    assert e["extra"]["http"]["user_agent"] == "sqlmap/1.8"


def test_key_value_and_json_and_fallback():
    _, kv = parse_line('src=10.0.0.1 dst=8.8.8.8 dpt=53 action=dns_query msg="lookup example"')
    assert kv["src_ip"] == "10.0.0.1" and kv["dst_port"] == 53 and kv["message"] == "lookup example"

    _, js = parse_line('{"action": "file_renamed", "category": "file", "file": {"path": "a.locked"}}')
    event = EventIn(**js)
    assert event.extra["file"]["path"] == "a.locked"

    name, fb = parse_line("something completely unstructured", default_host="h1")
    assert name == "fallback" and fb["host"] == "h1"
