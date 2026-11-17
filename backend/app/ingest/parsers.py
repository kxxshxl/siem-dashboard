"""Raw log line parsers.

Each parser turns one text line into a normalized event dict (the same shape accepted
by ``POST /api/events``) or returns ``None`` if the line is not in its format. Parsers
are tried in order; anything unrecognised becomes a generic ``other/log`` event so no
data is silently dropped.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

ParsedEvent = dict[str, Any]

_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_ISO_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_SSH_FAIL = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)"
    r"(?: port (?P<port>\d+))?"
)
_SSH_OK = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)(?: port (?P<port>\d+))?"
)
_SSH_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+)\s*:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$")
_KV = re.compile(r"(\w[\w.\-]*)=(\"[^\"]*\"|\S*)")
_ACCESS_LOG = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)(?:\s+\S+)?"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _syslog_time(raw: str) -> datetime:
    now = _now()
    parsed = datetime.strptime(f"{now.year} {' '.join(raw.split())}", "%Y %b %d %H:%M:%S")
    # Syslog omits the year; a December line read in January belongs to last year.
    if parsed > now and (parsed - now).days > 1:
        parsed = parsed.replace(year=now.year - 1)
    return parsed


def _iso_time(raw: str) -> datetime:
    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if dt.tzinfo:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_json(line: str) -> ParsedEvent | None:
    if not line.lstrip().startswith("{"):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    data.setdefault("source", "json")
    data.setdefault("category", "other")
    data.setdefault("action", "log")
    data.setdefault("message", "")
    return data


def _parse_program(prog: str, host: str, ts: datetime, msg: str) -> ParsedEvent:
    base: ParsedEvent = {
        "timestamp": ts,
        "host": host,
        "source": prog.split("/")[-1],
        "category": "other",
        "action": "log",
        "message": msg,
        "extra": {},
    }
    if prog.startswith("sshd"):
        base["category"] = "authentication"
        if m := _SSH_FAIL.search(msg):
            base.update(action="login_failure", severity="low", username=m["user"], src_ip=m["ip"])
            base["extra"]["auth_method"] = m["method"]
        elif m := _SSH_OK.search(msg):
            base.update(action="login_success", username=m["user"], src_ip=m["ip"])
            base["extra"]["auth_method"] = m["method"]
        elif m := _SSH_INVALID.search(msg):
            base.update(action="invalid_user", severity="low", username=m["user"], src_ip=m["ip"])
        else:
            base["action"] = "sshd_event"
        if base.get("src_ip"):
            base["dst_port"] = 22
    elif prog == "sudo" and (m := _SUDO.match(msg)):
        base.update(
            category="privilege",
            action="sudo",
            username=m["user"],
            extra={"target_user": m["target"], "process": {"cmdline": m["cmd"].strip()}},
        )
    elif prog == "kernel" and ("SRC=" in msg and "DST=" in msg):
        fields = dict(_KV.findall(msg))
        blocked = "BLOCK" in msg.upper() or "DROP" in msg.upper()
        base.update(
            source="firewall",
            category="network",
            action="connection_blocked" if blocked else "connection_allowed",
            severity="low" if blocked else "info",
            src_ip=fields.get("SRC"),
            dst_ip=fields.get("DST"),
            dst_port=int(fields["DPT"]) if fields.get("DPT", "").isdigit() else None,
            extra={"protocol": fields.get("PROTO"), "src_port": fields.get("SPT")},
        )
    return base


def parse_syslog(line: str) -> ParsedEvent | None:
    m = _SYSLOG.match(line)
    if m:
        try:
            ts = _syslog_time(m["ts"])
        except ValueError:
            return None
    else:
        m = _ISO_SYSLOG.match(line)
        if not m:
            return None
        try:
            ts = _iso_time(m["ts"])
        except ValueError:
            return None
    event = _parse_program(m["prog"], m["host"], ts, m["msg"])
    event["raw"] = line
    return event


def parse_access_log(line: str) -> ParsedEvent | None:
    m = _ACCESS_LOG.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
        ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        ts = _now()
    status = int(m["status"])
    return {
        "timestamp": ts,
        "source": "web",
        "category": "web",
        "action": "http_request",
        "severity": "low" if status >= 400 else "info",
        "src_ip": m["ip"],
        "username": None if m["user"] == "-" else m["user"],
        "message": f'{m["method"]} {m["uri"]} -> {status}',
        "extra": {
            "http": {
                "method": m["method"],
                "uri": m["uri"],
                "status": status,
                "bytes": 0 if m["size"] == "-" else int(m["size"]),
                "user_agent": m["agent"],
            }
        },
        "raw": line,
    }


def parse_key_value(line: str) -> ParsedEvent | None:
    pairs = _KV.findall(line)
    if len(pairs) < 2:
        return None
    fields: dict[str, Any] = {}
    for key, value in pairs:
        if value.startswith('"'):
            value = shlex.split(value)[0] if value != '""' else ""
        fields[key.lower()] = value
    aliases = {
        "src": "src_ip", "srcip": "src_ip", "source_ip": "src_ip",
        "dst": "dst_ip", "dstip": "dst_ip", "destination_ip": "dst_ip",
        "dpt": "dst_port", "dport": "dst_port", "port": "dst_port",
        "user": "username", "usr": "username",
        "hostname": "host", "msg": "message",
    }
    event: ParsedEvent = {"extra": {}, "raw": line}
    for key, value in fields.items():
        key = aliases.get(key, key)
        if key in {"src_ip", "dst_ip", "username", "host", "message", "source",
                   "category", "action", "severity"}:
            event[key] = value
        elif key == "dst_port":
            event[key] = int(value) if value.isdigit() else None
        elif key in {"timestamp", "time", "ts"}:
            try:
                event["timestamp"] = _iso_time(value)
            except ValueError:
                pass
        else:
            event["extra"][key] = int(value) if value.isdigit() else value
    event.setdefault("source", "kv")
    event.setdefault("category", "network" if event.get("dst_ip") else "other")
    event.setdefault("action", "log")
    event.setdefault("message", line[:500])
    return event


PARSERS: list[tuple[str, Callable[[str], ParsedEvent | None]]] = [
    ("json", parse_json),
    ("syslog", parse_syslog),
    ("access_log", parse_access_log),
    ("key_value", parse_key_value),
]


def parse_line(line: str, default_host: str | None = None) -> tuple[str, ParsedEvent]:
    """Return (parser_name, event) for one raw line."""
    line = line.rstrip("\r\n")
    for name, parser in PARSERS:
        event = parser(line)
        if event is not None:
            if default_host and not event.get("host"):
                event["host"] = default_host
            return name, event
    return "fallback", {
        "source": "raw",
        "category": "other",
        "action": "log",
        "host": default_host,
        "message": line[:2000],
        "raw": line,
    }
