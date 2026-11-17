from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from sqlalchemy import Integer, cast, func, select
from sqlalchemy.orm import Session

from ..deps import DB, CurrentUser
from ..models import SEVERITIES, Alert, Event, utcnow
from ..pipeline import detection_engine
from ..realtime import broadcaster
from ..schemas import AlertOut, _iso_utc
from ..simulator.noise import noise

router = APIRouter(prefix="/api/stats", tags=["stats"])

_BUCKETS = [60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600]


def _epoch(db: Session, column):
    if db.get_bind().dialect.name == "sqlite":
        return cast(func.strftime("%s", column), Integer)
    return cast(func.extract("epoch", column), Integer)


def _bucketed(db: Session, column, since: datetime, bucket: int, *filters) -> dict[int, int]:
    idx = (_epoch(db, column) / bucket).label("idx")
    stmt = select(cast(idx, Integer), func.count()).where(column >= since, *filters)
    stmt = stmt.group_by(cast(idx, Integer))
    return {int(i): c for i, c in db.execute(stmt) if i is not None}


@router.get("/overview")
def overview(db: DB, _: CurrentUser,
             hours: Annotated[int, Query(ge=1, le=168)] = 24) -> dict:
    now = utcnow()
    since = now - timedelta(hours=hours)
    bucket = next((b for b in _BUCKETS if b >= hours * 3600 / 60), _BUCKETS[-1])

    # ---- timeline (zero-filled). Datetimes are naive UTC, so measure from a naive epoch.
    epoch = datetime(1970, 1, 1)
    start_idx = int((since - epoch).total_seconds()) // bucket
    end_idx = int((now - epoch).total_seconds()) // bucket
    event_counts = _bucketed(db, Event.timestamp, since, bucket)
    # plot detections at the time the activity happened, not when the alert row was written
    alert_counts = _bucketed(db, Alert.first_seen, since, bucket)
    timeline = [
        {
            "t": _iso_utc(epoch + timedelta(seconds=i * bucket)),
            "events": event_counts.get(i, 0),
            "alerts": alert_counts.get(i, 0),
        }
        for i in range(start_idx, end_idx + 1)
    ]

    def grouped(column, *filters, limit: int | None = None, model=Event, ts=None):
        ts = ts if ts is not None else model.timestamp
        stmt = (select(column, func.count()).where(ts >= since, column.is_not(None), *filters)
                .group_by(column).order_by(func.count().desc()))
        if limit:
            stmt = stmt.limit(limit)
        return [(k, c) for k, c in db.execute(stmt)]

    events_total = db.scalar(select(func.count(Event.id)).where(Event.timestamp >= since)) or 0
    # Rate of live telemetry (by event time) - excludes back-filled / replayed history.
    recent_rate = db.scalar(
        select(func.count(Event.id)).where(
            Event.timestamp >= now - timedelta(minutes=5),
            Event.ingested_at >= now - timedelta(minutes=5),
        )
    ) or 0
    alert_sev = dict(grouped(Alert.severity, model=Alert, ts=Alert.created_at))
    alert_status = dict(grouped(Alert.status, model=Alert, ts=Alert.created_at))
    open_by_sev = dict(db.execute(
        select(Alert.severity, func.count()).where(Alert.status.in_(("open", "in_progress")))
        .group_by(Alert.severity)
    ).all())

    flagged = {
        part.split("=", 1)[1]
        for (entity,) in db.execute(select(Alert.entity).where(Alert.created_at >= since))
        for part in entity.split(", ")
        if part.startswith(("src_ip=", "dst_ip="))
    }
    top_sources = [
        {"ip": ip, "events": c, "flagged": ip in flagged}
        for ip, c in grouped(Event.src_ip, limit=8)
    ]

    recent = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(8)).unique().all()

    return {
        "range": {"hours": hours, "since": _iso_utc(since), "bucket_seconds": bucket},
        "totals": {
            "events": events_total,
            "events_all_time": db.scalar(select(func.count(Event.id))) or 0,
            "events_per_minute": round(recent_rate / 5, 1),
            "alerts": sum(alert_sev.values()),
            "open_alerts": sum(open_by_sev.values()),
            "open_critical": open_by_sev.get("critical", 0),
            "open_high": open_by_sev.get("high", 0),
        },
        "timeline": timeline,
        "alerts_by_severity": [{"name": s, "count": alert_sev.get(s, 0)} for s in SEVERITIES[1:]],
        "alerts_by_status": alert_status,
        "events_by_category": [{"name": k, "count": c} for k, c in grouped(Event.category)],
        "events_by_source": [{"name": k, "count": c} for k, c in grouped(Event.source, limit=8)],
        "top_sources": top_sources,
        "top_hosts": [{"name": k, "count": c} for k, c in grouped(Event.host, limit=8)],
        "mitre": [
            {"tactic": t, "technique": tech, "count": c}
            for t, tech, c in db.execute(
                select(Alert.mitre_tactic, Alert.mitre_technique, func.count())
                .where(Alert.created_at >= since, Alert.mitre_tactic.is_not(None))
                .group_by(Alert.mitre_tactic, Alert.mitre_technique)
                .order_by(func.count().desc())
            )
        ],
        "recent_alerts": [AlertOut.model_validate(a).model_dump(mode="json") for a in recent],
        "engine": {
            "rules_enabled": len(detection_engine.rules),
            "tracked_entities": detection_engine.tracked_entities,
            "live_clients": broadcaster.client_count,
            "noise_enabled": noise.running,
        },
    }
