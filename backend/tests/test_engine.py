from datetime import datetime, timedelta

import pytest

from app.detection import CompiledRule, DetectionEngine, validate_definition
from app.detection.conditions import matches

T0 = datetime(2026, 1, 1, 12, 0, 0)


def ev(i, seconds, **fields):
    return {"id": i, "timestamp": T0 + timedelta(seconds=seconds), **fields}


def rule(kind, definition, rid=1):
    validate_definition(kind, definition)
    return CompiledRule(id=rid, slug=f"r{rid}", name=f"Rule {rid}", kind=kind,
                        severity="high", definition=definition)


# ------------------------------------------------------------- conditions
@pytest.mark.parametrize("where, expected", [
    ({"action": "login_failure"}, True),
    ({"action": "login_success"}, False),
    ({"dst_port": [22, 3389]}, True),
    ({"dst_port": {"gte": 23}}, False),
    ({"message": {"contains": "FAILED"}}, True),
    ({"message": {"regex": r"from \d+\.\d+"}}, True),
    ({"src_ip": {"cidr": ["203.0.113.0/24"]}}, True),
    ({"src_ip": {"not_cidr": ["10.0.0.0/8"]}}, True),
    ({"http.status": 404}, True),
    ({"http.status": {"in": [200, 301]}}, False),
    ({"missing": {"exists": False}}, True),
    ({"any": [{"action": "nope"}, {"dst_port": 22}]}, True),
    ({"any": [{"action": "nope"}, {"dst_port": 23}]}, False),
])
def test_conditions(where, expected):
    record = {"action": "login_failure", "dst_port": 22, "src_ip": "203.0.113.9",
              "message": "Failed password from 203.0.113.9", "http": {"status": 404}}
    assert matches(record, where) is expected


@pytest.mark.parametrize("kind, definition", [
    ("threshold", {"where": {}, "group_by": ["src_ip"], "window_seconds": 60}),  # no count
    ("threshold", {"where": {}, "count": 5, "window_seconds": 60}),  # no group_by
    ("cardinality", {"group_by": ["src_ip"], "distinct": 5, "window_seconds": 60}),  # no field
    ("sequence", {"group_by": ["src_ip"], "window_seconds": 60, "steps": [{"where": {}}]}),
    ("match", {"where": {"x": {"bogus_op": 1}}}),
    ("match", {"where": {"x": {"regex": "("}}}),
    ("match", {"where": {"x": {"cidr": "not-a-cidr"}}}),
    ("nonsense", {}),
])
def test_invalid_definitions_rejected(kind, definition):
    with pytest.raises(ValueError):
        validate_definition(kind, definition)


# ----------------------------------------------------------------- kinds
def test_match_rule_fires_per_event():
    engine = DetectionEngine([rule("match", {"where": {"action": "bad"}, "group_by": ["host"]})])
    assert engine.process(ev(1, 0, action="bad", host="a"))
    assert not engine.process(ev(2, 1, action="good", host="a"))
    # missing group_by field -> cannot attribute, no detection
    assert not engine.process(ev(3, 2, action="bad"))


def test_threshold_respects_window():
    r = rule("threshold", {"where": {"action": "fail"}, "group_by": ["src_ip"],
                           "count": 3, "window_seconds": 10})
    engine = DetectionEngine([r])
    assert not engine.process(ev(1, 0, action="fail", src_ip="1.1.1.1"))
    assert not engine.process(ev(2, 5, action="fail", src_ip="1.1.1.1"))
    assert not engine.process(ev(3, 20, action="fail", src_ip="1.1.1.1"))  # first two expired
    assert not engine.process(ev(4, 22, action="fail", src_ip="2.2.2.2"))  # other entity
    out = engine.process(ev(5, 25, action="fail", src_ip="1.1.1.1")) or []
    assert out == []
    out = engine.process(ev(6, 26, action="fail", src_ip="1.1.1.1"))
    assert len(out) == 1
    assert out[0].entity == "src_ip=1.1.1.1"
    assert out[0].event_ids == [3, 5, 6]


def test_cardinality_counts_distinct_values():
    r = rule("cardinality", {"where": {}, "group_by": ["src_ip"], "field": "dst_port",
                             "distinct": 4, "window_seconds": 30})
    engine = DetectionEngine([r])
    for i, port in enumerate([22, 22, 80, 80, 443]):
        assert not engine.process(ev(i, i, src_ip="9.9.9.9", dst_port=port))
    out = engine.process(ev(10, 10, src_ip="9.9.9.9", dst_port=8080))
    assert len(out) == 1 and len(out[0].event_ids) == 4


def test_sequence_requires_order_and_window():
    r = rule("sequence", {
        "group_by": ["src_ip"], "window_seconds": 60,
        "steps": [{"where": {"action": "fail"}, "count": 3}, {"where": {"action": "ok"}}],
    })
    engine = DetectionEngine([r])
    # success before enough failures does nothing
    assert not engine.process(ev(1, 0, action="ok", src_ip="x"))
    for i in range(2, 5):
        assert not engine.process(ev(i, i, action="fail", src_ip="x"))
    out = engine.process(ev(5, 10, action="ok", src_ip="x"))
    assert len(out) == 1 and out[0].event_ids == [2, 3, 4, 5]

    # sequence that takes too long is restarted
    for i in range(10, 13):
        engine.process(ev(i, 100 + i, action="fail", src_ip="y"))
    assert not engine.process(ev(20, 300, action="ok", src_ip="y"))


def test_summary_template():
    r = rule("threshold", {"where": {}, "group_by": ["src_ip"], "count": 2, "window_seconds": 60,
                           "summary": "{count} hits from {src_ip} ({unknown})"})
    engine = DetectionEngine([r])
    engine.process(ev(1, 0, src_ip="5.5.5.5"))
    (d,) = engine.process(ev(2, 1, src_ip="5.5.5.5"))
    assert d.summary == "2 hits from 5.5.5.5 ({unknown})"
