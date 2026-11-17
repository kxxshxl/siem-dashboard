"""Every simulated attack must trip the rules it is designed to exercise, and benign
background traffic must not trip any rule (false-positive guard)."""

import random
from datetime import datetime, timedelta

import pytest
import yaml

from app.detection import CompiledRule, DetectionEngine
from app.detection.loader import DEFAULT_RULES_PATH
from app.schemas import EventIn
from app.simulator.noise import benign_event
from app.simulator.scenarios import SCENARIOS, build_timeline

T0 = datetime(2026, 1, 1, 12, 0, 0)


def default_engine() -> DetectionEngine:
    specs = yaml.safe_load(DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
    return DetectionEngine(
        CompiledRule(id=i, slug=s["slug"], name=s["name"], kind=s["kind"],
                     severity=s["severity"], definition=s["definition"])
        for i, s in enumerate(specs, start=1)
    )


def run(engine, records):
    fired = []
    for i, record in enumerate(sorted(records, key=lambda r: r["timestamp"]), start=1):
        fired += engine.process({**record, "id": i})
    return fired


def to_records(timeline, start=T0):
    out = []
    for offset, event in timeline:
        e = EventIn(**{**event, "timestamp": start + timedelta(seconds=offset)})
        record = dict(e.extra)
        record.update(e.model_dump(exclude={"extra", "raw"}))
        out.append(record)
    return out


@pytest.mark.parametrize("slug", list(SCENARIOS))
@pytest.mark.parametrize("seed", [1, 2, 3])
def test_scenario_triggers_expected_rules(slug, seed):
    scenario, _, timeline = build_timeline(slug, "203.0.113.66", None, random.Random(seed))
    fired = {d.rule.slug for d in run(default_engine(), to_records(timeline))}
    assert set(scenario.expected_rules) <= fired, f"{slug}: fired {fired}"


def test_password_spray_does_not_look_like_brute_force():
    _, _, timeline = build_timeline("password-spray", "203.0.113.66", None, random.Random(7))
    fired = {d.rule.slug for d in run(default_engine(), to_records(timeline))}
    assert "ssh-brute-force" not in fired


def test_benign_noise_raises_no_alerts():
    rng = random.Random(42)
    timeline = [(rng.uniform(0, 3600), benign_event(rng)) for _ in range(5000)]
    fired = run(default_engine(), to_records(timeline))
    assert fired == [], [d.rule.slug for d in fired]
