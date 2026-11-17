"""Turns scenario timelines into ingested events."""

from __future__ import annotations

import random
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from ..detection import DetectionEngine
from ..models import utcnow
from ..pipeline import detection_engine, ingest
from ..schemas import EventIn, IngestResult, SimulationResult
from .environment import external_ip
from .noise import benign_event
from .scenarios import SCENARIOS, build_timeline


def _anchor(timeline, end: datetime) -> list[EventIn]:
    span = max((offset for offset, _ in timeline), default=0)
    start = end - timedelta(seconds=span)
    events = []
    for offset, event in timeline:
        events.append(EventIn(**{**event, "timestamp": start + timedelta(seconds=offset)}))
    return events


def run_scenario(db: Session, slug: str, attacker_ip: str | None = None,
                 target_host: str | None = None) -> SimulationResult:
    if slug not in SCENARIOS:
        raise KeyError(slug)
    attacker = attacker_ip or external_ip()
    scenario, target, timeline = build_timeline(slug, attacker, target_host)
    result = ingest(db, _anchor(timeline, utcnow()))
    return SimulationResult(
        **result.model_dump(), scenario=scenario.slug, attacker_ip=attacker,
        target_host=target.name,
    )


def backfill(db: Session, hours: int = 24, events_per_hour: int = 120,
             seed: int | None = None) -> IngestResult:
    """Populate history: benign noise spread over ``hours`` plus each scenario once.

    Uses a throw-away engine (with the live rule set) so replaying old timestamps cannot
    disturb the sliding windows of the live engine.
    """
    rng = random.Random(seed)
    now = utcnow()
    engine = DetectionEngine(detection_engine.rules)
    events: list[EventIn] = []
    for _ in range(hours * events_per_hour):
        ts = now - timedelta(seconds=rng.uniform(0, hours * 3600))
        events.append(EventIn(**benign_event(rng, ts)))
    for slug in SCENARIOS:
        end = now - timedelta(seconds=rng.uniform(600, max(hours * 3600 - 600, 1200)))
        _, _, timeline = build_timeline(slug, external_ip(rng), None, rng)
        events.extend(_anchor(timeline, end))
    return ingest(db, events, engine=engine, live=False)
