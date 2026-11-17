from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, or_, select

from ..deps import DB, CurrentUser
from ..models import Alert, AlertNote, Event, utcnow
from ..realtime import broadcaster
from ..schemas import (
    AlertDetail,
    AlertOut,
    AlertPage,
    AlertUpdate,
    BulkAlertUpdate,
    EventOut,
    NoteIn,
    NoteOut,
    RuleOut,
)

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_STATUS_LABEL = {"open": "Open", "in_progress": "In progress", "resolved": "Resolved",
                 "dismissed": "Dismissed"}


@router.get("", response_model=AlertPage)
def list_alerts(
    db: DB,
    _: CurrentUser,
    status_: Annotated[str | None, Query(alias="status")] = None,
    severity: str | None = None,
    rule_id: int | None = None,
    tactic: str | None = None,
    q: str | None = None,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=200)] = 50,
) -> AlertPage:
    stmt = select(Alert)
    if status_:
        stmt = stmt.where(Alert.status.in_(status_.split(",")))
    if severity:
        stmt = stmt.where(Alert.severity.in_(severity.split(",")))
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if tactic:
        stmt = stmt.where(Alert.mitre_tactic == tactic)
    if q:
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Alert.title.ilike(like), Alert.summary.ilike(like),
                              Alert.entity.ilike(like), Alert.mitre_technique.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Alert.last_seen.desc(), Alert.id.desc())
        .offset((page - 1) * page_size).limit(page_size)
    ).unique().all()
    return AlertPage(items=[AlertOut.model_validate(a) for a in rows], total=total, page=page,
                     page_size=page_size)


def _get(db, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


def _detail(db, alert: Alert) -> AlertDetail:
    events = []
    if alert.event_ids:
        events = db.scalars(
            select(Event).where(Event.id.in_(alert.event_ids)).order_by(Event.timestamp)
        ).all()
    detail = AlertDetail.model_validate(alert)
    detail.events = [EventOut.model_validate(e) for e in events]
    detail.notes = [NoteOut.model_validate(n) for n in alert.notes]
    detail.rule = RuleOut.model_validate(alert.rule) if alert.rule else None
    return detail


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, db: DB, _: CurrentUser) -> AlertDetail:
    return _detail(db, _get(db, alert_id))


@router.patch("/{alert_id}", response_model=AlertDetail)
def update_alert(alert_id: int, body: AlertUpdate, db: DB, user: CurrentUser) -> AlertDetail:
    alert = _get(db, alert_id)
    if body.status and body.status != alert.status:
        alert.notes.append(AlertNote(
            author=user.username,
            body=f"Status changed: {_STATUS_LABEL[alert.status]} -> {_STATUS_LABEL[body.status]}",
        ))
        alert.status = body.status
        if body.status == "in_progress" and not alert.assignee:
            alert.assignee = user.username
    if body.assignee is not None:
        alert.assignee = body.assignee or None
    if body.note:
        alert.notes.append(AlertNote(author=user.username, body=body.note))
    alert.updated_at = utcnow()
    db.commit()
    db.refresh(alert)
    broadcaster.publish("alert_updated", AlertOut.model_validate(alert).model_dump(mode="json"))
    return _detail(db, alert)


@router.post("/{alert_id}/notes", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def add_note(alert_id: int, body: NoteIn, db: DB, user: CurrentUser) -> AlertNote:
    alert = _get(db, alert_id)
    note = AlertNote(author=user.username, body=body.body)
    alert.notes.append(note)
    db.commit()
    return note


@router.post("/bulk", response_model=dict)
def bulk_update(body: BulkAlertUpdate, db: DB, user: CurrentUser) -> dict:
    alerts = db.scalars(select(Alert).where(Alert.id.in_(body.ids))).unique().all()
    changed = 0
    for alert in alerts:
        if alert.status != body.status:
            alert.notes.append(AlertNote(
                author=user.username,
                body=f"Status changed (bulk): {_STATUS_LABEL[alert.status]} -> "
                     f"{_STATUS_LABEL[body.status]}",
            ))
            alert.status = body.status
            alert.updated_at = utcnow()
            changed += 1
    db.commit()
    for alert in alerts:
        broadcaster.publish("alert_updated", AlertOut.model_validate(alert).model_dump(mode="json"))
    return {"updated": changed}


def rule_alert_counts(db) -> dict[int, int]:
    rows = db.execute(select(Alert.rule_id, func.count(Alert.id)).group_by(Alert.rule_id))
    return {rule_id: count for rule_id, count in rows if rule_id is not None}
