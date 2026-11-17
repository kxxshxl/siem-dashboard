"""Benign background telemetry so detections have something realistic to stand out from."""

from __future__ import annotations

import logging
import random
import threading
from datetime import datetime
from typing import Any

from .environment import HOSTS, USERS, external_ip

log = logging.getLogger(__name__)

_PAGES = ["/", "/products", "/products.php?id=3", "/about", "/contact", "/static/app.js",
          "/static/site.css", "/api/v1/cart", "/login", "/search?q=boots", "/favicon.ico"]
_DOMAINS = ["github.com", "login.microsoftonline.com", "slack.com", "updates.example.com",
            "fonts.googleapis.com", "s3.amazonaws.com", "pypi.org", "registry.npmjs.org"]
_PROCS = [("chrome.exe", "chrome.exe --type=renderer"), ("outlook.exe", "OUTLOOK.EXE"),
          ("teams.exe", "Teams.exe --process-start-reason=AutoStart"),
          ("code.exe", "Code.exe ."), ("python3", "python3 manage.py runserver"),
          ("cron", "/usr/sbin/CRON -f"), ("systemd", "/lib/systemd/systemd --user")]


def benign_event(rng: random.Random, ts: datetime | None = None) -> dict[str, Any]:
    roll = rng.random()
    h = rng.choice(HOSTS)
    user = rng.choice(USERS[:6])
    internal = f"10.0.5.{rng.randint(20, 80)}"
    if roll < 0.32:
        web = rng.choice([x for x in HOSTS if x.name.startswith("web")])
        page = rng.choice(_PAGES)
        status = rng.choices([200, 304, 301, 404], weights=[80, 10, 5, 5])[0]
        event = {"source": "nginx", "category": "web", "action": "http_request",
                 "host": web.name, "src_ip": external_ip(rng), "dst_ip": web.ip, "dst_port": 443,
                 "severity": "low" if status >= 400 else "info",
                 "message": f"GET {page} -> {status}",
                 "extra": {"http": {"method": "GET", "uri": page, "status": status,
                                    "user_agent": "Mozilla/5.0"}}}
    elif roll < 0.52:
        domain = rng.choice(_DOMAINS)
        event = {"source": "dns", "category": "dns", "action": "dns_query", "host": h.name,
                 "src_ip": h.ip, "message": f"Query A {domain}",
                 "extra": {"dns": {"query": domain}}}
    elif roll < 0.70:
        port = rng.choice([443, 443, 443, 80, 53, 123])
        event = {"source": "firewall", "category": "network", "action": "connection_allowed",
                 "host": h.name, "src_ip": h.ip, "dst_ip": external_ip(rng), "dst_port": port,
                 "message": f"ALLOW TCP {h.ip} -> :{port}",
                 "extra": {"bytes_out": rng.randint(400, 900_000),
                           "bytes_in": rng.randint(400, 5_000_000)}}
    elif roll < 0.86:
        image, cmd = rng.choice(_PROCS)
        event = {"source": "edr", "category": "process", "action": "process_start",
                 "host": h.name, "username": user, "message": f"{image} started by {user}",
                 "extra": {"process": {"image": image, "cmdline": cmd}}}
    else:
        ok = rng.random() > 0.08  # the occasional typo'd password
        event = {"source": "sshd" if h.os == "linux" else "windows-security",
                 "category": "authentication",
                 "action": "login_success" if ok else "login_failure",
                 "severity": "info" if ok else "low",
                 "host": h.name, "username": user, "src_ip": internal, "dst_ip": h.ip,
                 "dst_port": 22 if h.os == "linux" else 3389,
                 "message": f"{'Accepted' if ok else 'Failed'} password for {user} from {internal}"}
    if ts is not None:
        event["timestamp"] = ts
    return event


class NoiseGenerator:
    """Background thread that continuously ingests benign events."""

    def __init__(self) -> None:
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.rate = 2.0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, rate: float) -> None:
        self.rate = rate
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="vigil-noise", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _run(self) -> None:
        from ..database import SessionLocal
        from ..pipeline import ingest
        from ..schemas import EventIn

        rng = random.Random()
        while not self._stop.is_set():
            # Batch per second to keep DB round-trips low at higher rates.
            batch_size = max(1, round(self.rate))
            interval = batch_size / self.rate
            try:
                with SessionLocal() as db:
                    ingest(db, [EventIn(**benign_event(rng)) for _ in range(batch_size)])
            except Exception:  # noqa: BLE001 - keep the generator alive on transient DB errors
                log.exception("noise generator batch failed")
            self._stop.wait(interval)


noise = NoiseGenerator()
