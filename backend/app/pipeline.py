"""Ingestion pipeline: persist events -> run detection -> create / merge alerts -> broadcast."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .detection import Detection, DetectionEngine
from .models import Alert, Event, utcnow
from .realtime import broadcaster
from .schemas import AlertOut, EventIn, EventOut, IngestResult

# Serialises ingestion so events are evaluated in order and alert de-duplication
# cannot race between concurrent requests / the background noise generator.
_INGEST_LOCK = threading.Lock()
_MAX_EVENT_IDS_PER_ALERT = 500
_MAX_LIVE_EVENTS_PER_BATCH = 50

detection_engine = DetectionEngine()


def ingest(
    db: Session,
    items: Iterable[EventIn],
    *,
    engine: DetectionEngine | None = None,
    parsers: dict[str, int] | None = None,
    live: bool = True,
) -> IngestResult:
    engine = engine or detection_engine
    rows = []
    for item in items:
        data = item.model_dump()
        data["timestamp"] = data["timestamp"] or utcnow()
        rows.append(Event(**data))
    rows.sort(key=lambda r: r.timestamp)

    created: dict[int, Alert] = {}
    updated: dict[int, Alert] = {}
    with _INGEST_LOCK:
        db.add_all(rows)
        db.flush()  # assign primary keys so alerts can reference events
        for row in rows:
            for detection in engine.process(row.as_detection_record()):
                alert, is_new = _upsert_alert(db, detection)
                (created if is_new else updated)[alert.id] = alert
        db.commit()

    for alert_id in created:
        updated.pop(alert_id, None)

    if live:
        for row in rows[-_MAX_LIVE_EVENTS_PER_BATCH:]:
            broadcaster.publish("event", EventOut.model_validate(row).model_dump(mode="json"))
        for alert in created.values():
            broadcaster.publish("alert", AlertOut.model_validate(alert).model_dump(mode="json"))
        for alert in updated.values():
            broadcaster.publish(
                "alert_updated", AlertOut.model_validate(alert).model_dump(mode="json")
            )
        if rows:
            broadcaster.publish("ingest", {"count": len(rows)})

    return IngestResult(
        accepted=len(rows),
        alerts_created=len(created),
        alerts_updated=len(updated),
        alert_ids=sorted({*created, *updated}),
        parsers=parsers or {},
    )


def _upsert_alert(db: Session, d: Detection) -> tuple[Alert, bool]:
    """Fold a detection into an active alert for the same rule + entity, or open a new one."""
    horizon = d.first_seen - timedelta(minutes=settings.alert_dedup_minutes)
    entity = d.entity[:200]  # column width; Postgres enforces it, SQLite does not
    existing = db.scalars(
        select(Alert)
        .where(
            Alert.rule_id == d.rule.id,
            Alert.entity == entity,
            Alert.status.in_(("open", "in_progress")),
            Alert.last_seen >= horizon,
        )
        .order_by(Alert.last_seen.desc())
        .limit(1)
    ).first()

    if existing:
        merged = list(dict.fromkeys([*existing.event_ids, *d.event_ids]))
        existing.event_ids = merged[-_MAX_EVENT_IDS_PER_ALERT:]
        existing.hit_count += 1
        existing.last_seen = max(existing.last_seen, d.last_seen)
        existing.summary = d.summary
        existing.updated_at = utcnow()
        db.flush()
        return existing, False

    alert = Alert(
        rule_id=d.rule.id,
        title=d.rule.name,
        summary=d.summary,
        severity=d.rule.severity,
        status="open",
        entity=entity,
        mitre_tactic=d.rule.mitre_tactic,
        mitre_technique=d.rule.mitre_technique,
        event_ids=d.event_ids[-_MAX_EVENT_IDS_PER_ALERT:],
        hit_count=1,
        first_seen=d.first_seen,
        last_seen=d.last_seen,
    )
    db.add(alert)
    db.flush()
    return alert, True
