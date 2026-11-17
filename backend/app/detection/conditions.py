"""Field-condition matching used by every rule kind.

A condition block ("where") is a mapping of field name -> expectation:

    where:
      action: login_failure            # equality
      dst_port: [22, 3389]             # membership
      src_ip: {not_cidr: [10.0.0.0/8]} # operator form
      any:                             # OR of nested blocks
        - {message: {contains: vssadmin}}
        - {message: {contains: wbadmin}}

All entries in a block must hold (logical AND). Field lookups support dotted paths
for nested values in the event's ``extra`` payload (e.g. ``process.cmdline``).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping
from functools import lru_cache
from typing import Any

_MISSING = object()


def resolve(record: Mapping[str, Any], path: str) -> Any:
    if path in record:
        return record[path]
    current: Any = record
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        else:
            return _MISSING
    return current


@lru_cache(maxsize=512)
def _regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


@lru_cache(maxsize=256)
def _network(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr, strict=False)


def _in_cidrs(value: Any, cidrs: Any) -> bool:
    if value in (None, _MISSING):
        return False
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    nets = cidrs if isinstance(cidrs, list) else [cidrs]
    return any(addr in _network(str(n)) for n in nets)


def _num(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _cmp(fn: Callable[[float, float], bool]) -> Callable[[Any, Any], bool]:
    def inner(value: Any, arg: Any) -> bool:
        a, b = _num(value), _num(arg)
        return a is not None and b is not None and fn(a, b)

    return inner


def _text(value: Any) -> str:
    return "" if value in (None, _MISSING) else str(value).lower()


OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda v, a: v == a,
    "ne": lambda v, a: v != a,
    "in": lambda v, a: v in a,
    "not_in": lambda v, a: v not in a,
    "contains": lambda v, a: str(a).lower() in _text(v),
    "not_contains": lambda v, a: str(a).lower() not in _text(v),
    "startswith": lambda v, a: _text(v).startswith(str(a).lower()),
    "endswith": lambda v, a: _text(v).endswith(str(a).lower()),
    "regex": lambda v, a: v not in (None, _MISSING) and bool(_regex(str(a)).search(str(v))),
    "gt": _cmp(lambda x, y: x > y),
    "gte": _cmp(lambda x, y: x >= y),
    "lt": _cmp(lambda x, y: x < y),
    "lte": _cmp(lambda x, y: x <= y),
    "exists": lambda v, a: (v not in (None, _MISSING)) == bool(a),
    "cidr": _in_cidrs,
    "not_cidr": lambda v, a: v not in (None, _MISSING) and not _in_cidrs(v, a),
}


def matches(record: Mapping[str, Any], where: Mapping[str, Any] | None) -> bool:
    if not where:
        return True
    for field, expected in where.items():
        if field == "any":
            if not any(matches(record, block) for block in expected):
                return False
            continue
        value = resolve(record, field)
        if isinstance(expected, Mapping):
            for op, arg in expected.items():
                if not OPERATORS[op](value, arg):
                    return False
        elif isinstance(expected, list):
            if value not in expected:
                return False
        elif value != expected:
            return False
    return True


def validate_where(where: Any, path: str = "where") -> None:
    """Raise ValueError if a condition block is malformed."""
    if where is None:
        return
    if not isinstance(where, Mapping):
        raise ValueError(f"{path} must be a mapping of field -> condition")
    for field, expected in where.items():
        if field == "any":
            if not isinstance(expected, list) or not expected:
                raise ValueError(f"{path}.any must be a non-empty list of condition blocks")
            for i, block in enumerate(expected):
                validate_where(block, f"{path}.any[{i}]")
            continue
        if isinstance(expected, Mapping):
            for op, arg in expected.items():
                if op not in OPERATORS:
                    raise ValueError(f"{path}.{field}: unknown operator '{op}'")
                if op == "regex":
                    try:
                        re.compile(str(arg))
                    except re.error as exc:
                        raise ValueError(f"{path}.{field}: invalid regex ({exc})") from exc
                if op in {"cidr", "not_cidr"}:
                    for net in arg if isinstance(arg, list) else [arg]:
                        try:
                            _network(str(net))
                        except ValueError as exc:
                            raise ValueError(f"{path}.{field}: invalid CIDR '{net}'") from exc
                if op in {"in", "not_in"} and not isinstance(arg, list):
                    raise ValueError(f"{path}.{field}: '{op}' expects a list")
