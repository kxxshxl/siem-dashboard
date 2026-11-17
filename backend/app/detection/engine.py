"""Streaming correlation engine.

Events are fed one at a time (in timestamp order) and evaluated against every enabled
rule. Stateful rule kinds keep sliding windows per *entity* - the combination of the
rule's ``group_by`` field values (e.g. ``src_ip=203.0.113.7``). Windows are measured in
event time, not wall-clock time, so replayed or back-filled logs correlate correctly.

Rule kinds
----------
match        fires on every event satisfying ``where``
threshold    fires when ``count`` matching events occur within ``window_seconds``
cardinality  fires when ``field`` takes ``distinct`` different values within the window
             (port scans, password spraying, lateral movement fan-out)
sequence     fires when ordered ``steps`` complete within the window
             (e.g. N failed logins followed by a success)
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .conditions import _MISSING, matches, resolve, validate_where

KINDS = ("match", "threshold", "cardinality", "sequence")
_PRUNE_EVERY = 500


@dataclass(frozen=True)
class CompiledRule:
    id: int
    slug: str
    name: str
    kind: str
    severity: str
    definition: Mapping[str, Any]
    mitre_tactic: str | None = None
    mitre_technique: str | None = None

    @property
    def group_by(self) -> list[str]:
        return list(self.definition.get("group_by") or [])

    @property
    def window(self) -> timedelta:
        return timedelta(seconds=int(self.definition.get("window_seconds", 60)))


@dataclass
class Detection:
    rule: CompiledRule
    entity: str
    event_ids: list[int]
    first_seen: datetime
    last_seen: datetime
    summary: str


@dataclass
class _Window:
    """Per-(rule, entity) state."""

    last_activity: datetime
    hits: deque = field(default_factory=deque)  # (timestamp, event_id) for threshold
    values: dict = field(default_factory=dict)  # value -> (timestamp, event_id) for cardinality
    step: int = 0  # sequence progress
    step_hits: int = 0
    started: datetime | None = None
    seq_ids: list[int] = field(default_factory=list)


def validate_definition(kind: str, definition: Mapping[str, Any]) -> None:
    """Raise ValueError when a rule definition cannot be executed."""
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {', '.join(KINDS)}")
    if not isinstance(definition, Mapping):
        raise ValueError("definition must be an object")
    group_by = definition.get("group_by", [])
    if not isinstance(group_by, list) or not all(isinstance(g, str) for g in group_by):
        raise ValueError("group_by must be a list of field names")

    def positive_int(key: str, default: int | None = None) -> None:
        value = definition.get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{key} must be a positive integer")

    if kind != "sequence":
        validate_where(definition.get("where"))
    if kind in {"threshold", "cardinality", "sequence"}:
        positive_int("window_seconds")
        if not group_by:
            raise ValueError(f"{kind} rules need at least one group_by field")
    if kind == "threshold":
        positive_int("count")
    if kind == "cardinality":
        if not isinstance(definition.get("field"), str):
            raise ValueError("cardinality rules need a 'field' to count distinct values of")
        positive_int("distinct")
    if kind == "sequence":
        steps = definition.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            raise ValueError("sequence rules need at least two steps")
        for i, step in enumerate(steps):
            if not isinstance(step, Mapping):
                raise ValueError(f"steps[{i}] must be an object")
            validate_where(step.get("where"), f"steps[{i}].where")
            count = step.get("count", 1)
            if not isinstance(count, int) or isinstance(count, bool) or count < 1:
                raise ValueError(f"steps[{i}].count must be a positive integer")


class DetectionEngine:
    def __init__(self, rules: Iterable[CompiledRule] = ()) -> None:
        self._lock = threading.Lock()
        self._rules: list[CompiledRule] = []
        self._state: dict[tuple[int, str], _Window] = {}
        self._processed = 0
        self.load(rules)

    # ------------------------------------------------------------------ rules
    def load(self, rules: Iterable[CompiledRule]) -> None:
        with self._lock:
            self._rules = list(rules)
            live = {r.id for r in self._rules}
            self._state = {k: v for k, v in self._state.items() if k[0] in live}

    def reset_rule(self, rule_id: int) -> None:
        with self._lock:
            self._state = {k: v for k, v in self._state.items() if k[0] != rule_id}

    def clear_state(self) -> None:
        with self._lock:
            self._state.clear()

    @property
    def rules(self) -> list[CompiledRule]:
        return list(self._rules)

    # -------------------------------------------------------------- evaluation
    def process(self, record: Mapping[str, Any]) -> list[Detection]:
        ts: datetime = record["timestamp"]
        detections: list[Detection] = []
        with self._lock:
            for rule in self._rules:
                detection = self._evaluate(rule, record, ts)
                if detection:
                    detections.append(detection)
            self._processed += 1
            if self._processed % _PRUNE_EVERY == 0:
                self._prune(ts)
        return detections

    def _entity(self, rule: CompiledRule, record: Mapping[str, Any]) -> str | None:
        parts = []
        for key in rule.group_by:
            value = resolve(record, key)
            if value in (None, "", _MISSING):
                return None  # cannot correlate without the grouping field
            parts.append(f"{key}={value}")
        return ", ".join(parts)

    def _window_for(self, rule: CompiledRule, entity: str, ts: datetime) -> _Window:
        key = (rule.id, entity)
        win = self._state.get(key)
        if win is None:
            win = self._state[key] = _Window(last_activity=ts)
        win.last_activity = max(win.last_activity, ts)
        return win

    def _evaluate(self, rule: CompiledRule, record: Mapping[str, Any], ts: datetime):
        d = rule.definition
        if rule.kind == "sequence":
            return self._evaluate_sequence(rule, record, ts)
        if not matches(record, d.get("where")):
            return None
        entity = self._entity(rule, record)
        if entity is None:
            return None
        event_id = record.get("id")

        if rule.kind == "match":
            return self._detect(rule, entity, [event_id], ts, ts, record, hits=1)

        win = self._window_for(rule, entity, ts)
        cutoff = ts - rule.window

        if rule.kind == "threshold":
            win.hits.append((ts, event_id))
            while win.hits and win.hits[0][0] < cutoff:
                win.hits.popleft()
            if len(win.hits) >= int(d["count"]):
                ids = [eid for _, eid in win.hits]
                first = win.hits[0][0]
                win.hits.clear()
                return self._detect(rule, entity, ids, first, ts, record, hits=len(ids))
            return None

        if rule.kind == "cardinality":
            value = resolve(record, d["field"])
            if value in (None, "", _MISSING):
                return None
            win.values[value] = (ts, event_id)
            win.values = {v: hit for v, hit in win.values.items() if hit[0] >= cutoff}
            if len(win.values) >= int(d["distinct"]):
                hits = sorted(win.values.values(), key=lambda h: h[0])
                win.values = {}
                return self._detect(
                    rule, entity, [eid for _, eid in hits], hits[0][0], ts, record, hits=len(hits)
                )
            return None
        return None

    def _evaluate_sequence(self, rule: CompiledRule, record: Mapping[str, Any], ts: datetime):
        steps = rule.definition["steps"]
        entity = self._entity(rule, record)
        if entity is None:
            return None
        key = (rule.id, entity)
        win = self._state.get(key)

        # Expire a sequence that took too long, then re-evaluate this event from step 0.
        if win and win.started and ts - win.started > rule.window:
            win.step, win.step_hits, win.started, win.seq_ids = 0, 0, None, []

        step_index = win.step if win else 0
        if not matches(record, steps[step_index].get("where")):
            return None

        win = self._window_for(rule, entity, ts)
        if win.started is None:
            win.started = ts
        win.step_hits += 1
        win.seq_ids.append(record.get("id"))
        if win.step_hits >= int(steps[win.step].get("count", 1)):
            win.step += 1
            win.step_hits = 0
        if win.step < len(steps):
            return None

        ids, first = win.seq_ids, win.started
        self._state.pop(key, None)
        return self._detect(rule, entity, ids, first, ts, record, hits=len(ids))

    def _detect(self, rule, entity, ids, first, last, record, hits) -> Detection:
        return Detection(
            rule=rule,
            entity=entity,
            event_ids=[i for i in ids if i is not None],
            first_seen=first,
            last_seen=last,
            summary=self._summary(rule, entity, record, hits, first, last),
        )

    @staticmethod
    def _summary(rule, entity, record, hits, first, last) -> str:
        template = rule.definition.get("summary")
        context = {k: v for k, v in record.items() if isinstance(v, (str, int, float))}
        context.update(
            count=hits, entity=entity or "n/a", seconds=int((last - first).total_seconds())
        )
        if template:
            try:
                return str(template).format_map(_SafeDict(context))
            except (ValueError, IndexError):
                pass
        if rule.kind == "match":
            return f"{rule.name}: {record.get('message') or record.get('action')}"
        return f"{rule.name} - {hits} events for {entity or 'n/a'} in {context['seconds']}s"

    def _prune(self, now: datetime) -> None:
        windows = {r.id: r.window for r in self._rules}
        self._state = {
            k: v
            for k, v in self._state.items()
            if k[0] in windows and now - v.last_activity <= windows[k[0]] * 2
        }

    @property
    def tracked_entities(self) -> int:
        return len(self._state)


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"
