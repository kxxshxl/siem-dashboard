"""A small fictional corporate network used by the simulator."""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Host:
    name: str
    ip: str
    os: str
    role: str


HOSTS: list[Host] = [
    Host("dc-01", "10.0.0.5", "windows", "domain controller"),
    Host("web-01", "10.0.1.10", "linux", "public web server"),
    Host("web-02", "10.0.1.11", "linux", "public web server"),
    Host("db-01", "10.0.2.20", "linux", "customer database"),
    Host("fs-01", "10.0.2.30", "windows", "file server"),
    Host("wks-alice", "10.0.5.21", "windows", "workstation"),
    Host("wks-bob", "10.0.5.22", "windows", "workstation"),
    Host("wks-carol", "10.0.5.23", "windows", "workstation"),
]
HOSTS_BY_NAME = {h.name: h for h in HOSTS}

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "svc_backup", "deploy"]

# RFC 5737 documentation ranges - always "external" and never routable in real life.
_EXTERNAL_PREFIXES = ["203.0.113.", "198.51.100.", "192.0.2."]


def external_ip(rng: random.Random | None = None) -> str:
    rng = rng or random
    return f"{rng.choice(_EXTERNAL_PREFIXES)}{rng.randint(2, 254)}"


def host(name: str | None, default: str) -> Host:
    return HOSTS_BY_NAME.get(name or "", HOSTS_BY_NAME[default])
