from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Query, status
from pydantic import ValidationError
from sqlalchemy import func, or_, select

from ..deps import DB, CurrentUser, IngestPrincipal
from ..ingest.parsers import parse_line
from ..models import Event
from ..pipeline import ingest
from ..schemas import EventIn, EventOut, EventPage, IngestResult, RawIngest, to_naive_utc

router = APIRouter(prefix="/api/events", tags=["events"])

MAX_BATCH = 5000


@router.get("", response_model=EventPage)
def list_events(
    db: DB,
    _: CurrentUser,
    q: str | None = None,
    category: str | None = None,
    source: str | None = None,
    severity: str | None = None,
    action: str | None = None,
    host: str | None = None,
    src_ip: str | None = None,
    username: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> EventPage:
    stmt = select(Event)
    for column, value in [
        (Event.category, category), (Event.source, source), (Event.action, action),
        (Event.host, host), (Event.src_ip, src_ip), (Event.username, username),
    ]:
        if value:
            stmt = stmt.where(column == value)
    if severity:
        stmt = stmt.where(Event.severity.in_(severity.split(",")))
    if since:
        stmt = stmt.where(Event.timestamp >= to_naive_utc(since))
    if until:
        stmt = stmt.where(Event.timestamp <= to_naive_utc(until))
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(
            Event.message.ilike(like), Event.host.ilike(like), Event.username.ilike(like),
            Event.src_ip.ilike(like), Event.dst_ip.ilike(like), Event.action.ilike(like),
        ))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Event.timestamp.desc(), Event.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return EventPage(items=[EventOut.model_validate(r) for r in rows], total=total, page=page,
                     page_size=page_size)


@router.get("/facets")
def facets(db: DB, _: CurrentUser) -> dict[str, list[str]]:
    def distinct(column) -> list[str]:
        return sorted(v for v in db.scalars(select(column).distinct().limit(200)) if v)

    return {
        "category": distinct(Event.category),
        "source": distinct(Event.source),
        "host": distinct(Event.host),
        "action": distinct(Event.action),
    }


@router.get("/{event_id}", response_model=EventOut)
def get_event(event_id: int, db: DB, _: CurrentUser) -> Event:
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    return event


@router.post("", response_model=IngestResult, status_code=status.HTTP_202_ACCEPTED)
def ingest_events(
    db: DB,
    _: IngestPrincipal,
    body: Annotated[EventIn | list[EventIn], Body()],
) -> IngestResult:
    """Ingest one structured event or a JSON array of events."""
    items = body if isinstance(body, list) else [body]
    if len(items) > MAX_BATCH:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"At most {MAX_BATCH} events per request")
    return ingest(db, items)


def _parse_raw(body: RawIngest) -> tuple[list[EventIn], Counter, list[dict]]:
    lines = [ln for ln in body.text.splitlines() if ln.strip()]
    if len(lines) > MAX_BATCH:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"At most {MAX_BATCH} lines per request")
    events, used, errors = [], Counter(), []
    for number, line in enumerate(lines, start=1):
        parser, data = parse_line(line, body.host)
        try:
            events.append(EventIn(**data))
            used[parser] += 1
        except ValidationError as exc:
            errors.append({"line": number, "error": exc.errors()[0]["msg"]})
    return events, used, errors


@router.post("/raw", response_model=IngestResult, status_code=status.HTTP_202_ACCEPTED)
def ingest_raw(body: RawIngest, db: DB, _: IngestPrincipal) -> IngestResult:
    """Ingest raw log text (syslog/auth.log, UFW, nginx access, key=value or JSON lines)."""
    events, used, _errors = _parse_raw(body)
    return ingest(db, events, parsers=dict(used))


@router.post("/parse")
def preview_parse(body: RawIngest, _: CurrentUser) -> dict:
    """Show how raw lines would be normalised, without storing anything."""
    events, used, errors = _parse_raw(body)
    return {
        "parsers": dict(used),
        "errors": errors,
        "events": [e.model_dump(mode="json") for e in events[:200]],
    }
