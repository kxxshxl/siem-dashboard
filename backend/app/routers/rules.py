from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from ..deps import DB, AdminUser, CurrentUser
from ..detection import CompiledRule, DetectionEngine, validate_definition
from ..detection.loader import reload_engine
from ..models import Event, Rule, utcnow
from ..pipeline import detection_engine
from ..schemas import RuleCreate, RuleOut, RuleTestRequest, RuleTestResult, RuleUpdate
from .alerts import rule_alert_counts

router = APIRouter(prefix="/api/rules", tags=["rules"])

_BACKTEST_EVENT_LIMIT = 50_000


def _out(rule: Rule, counts: dict[int, int]) -> RuleOut:
    out = RuleOut.model_validate(rule)
    out.alert_count = counts.get(rule.id, 0)
    return out


def _validate(kind: str, definition: dict) -> None:
    try:
        validate_definition(kind, definition)
    except ValueError as exc:
        raise HTTPException(422, f"Invalid rule: {exc}") from exc


@router.get("", response_model=list[RuleOut])
def list_rules(db: DB, _: CurrentUser) -> list[RuleOut]:
    counts = rule_alert_counts(db)
    return [_out(r, counts) for r in db.scalars(select(Rule).order_by(Rule.id))]


@router.get("/{rule_id}", response_model=RuleOut)
def get_rule(rule_id: int, db: DB, _: CurrentUser) -> RuleOut:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    return _out(rule, rule_alert_counts(db))


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(body: RuleCreate, db: DB, _: AdminUser) -> RuleOut:
    _validate(body.kind, body.definition)
    if db.scalars(select(Rule).where(Rule.slug == body.slug)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "A rule with this slug already exists")
    rule = Rule(**body.model_dump(), builtin=False)
    db.add(rule)
    db.commit()
    reload_engine(db, detection_engine)
    return _out(rule, {})


@router.patch("/{rule_id}", response_model=RuleOut)
def update_rule(rule_id: int, body: RuleUpdate, db: DB, _: AdminUser) -> RuleOut:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    changes = body.model_dump(exclude_unset=True)
    if "definition" in changes:
        _validate(rule.kind, changes["definition"])
    for key, value in changes.items():
        setattr(rule, key, value)
    rule.updated_at = utcnow()
    db.commit()
    if "definition" in changes:
        detection_engine.reset_rule(rule.id)  # old window state no longer applies
    reload_engine(db, detection_engine)
    return _out(rule, rule_alert_counts(db))


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: int, db: DB, _: AdminUser) -> None:
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Rule not found")
    if rule.builtin:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Built-in rules cannot be deleted; disable them instead")
    db.delete(rule)
    db.commit()
    reload_engine(db, detection_engine)


@router.post("/test", response_model=RuleTestResult)
def backtest_rule(body: RuleTestRequest, db: DB, _: CurrentUser) -> RuleTestResult:
    """Replay recent stored events through a draft rule without creating alerts."""
    _validate(body.kind, body.definition)
    draft = CompiledRule(id=-1, slug="draft", name="Draft rule", kind=body.kind,
                         severity="medium", definition=body.definition)
    engine = DetectionEngine([draft])
    since = utcnow() - timedelta(minutes=body.lookback_minutes)
    events = db.scalars(
        select(Event).where(Event.timestamp >= since)
        .order_by(Event.timestamp, Event.id).limit(_BACKTEST_EVENT_LIMIT)
    ).all()
    detections = []
    for event in events:
        for d in engine.process(event.as_detection_record()):
            detections.append({
                "entity": d.entity,
                "summary": d.summary,
                "event_ids": d.event_ids[:50],
                "event_count": len(d.event_ids),
                "first_seen": d.first_seen.isoformat() + "Z",
                "last_seen": d.last_seen.isoformat() + "Z",
            })
    return RuleTestResult(events_scanned=len(events), detections=detections[-200:])
