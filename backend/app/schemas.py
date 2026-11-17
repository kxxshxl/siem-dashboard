"""Pydantic request / response models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    computed_field,
    field_validator,
    model_validator,
)

from .models import ALERT_STATUSES, RULE_KINDS, SEVERITIES


def _iso_utc(value: datetime) -> str:
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.isoformat(timespec="milliseconds") + "Z"


UTCDatetime = Annotated[datetime, PlainSerializer(_iso_utc, return_type=str)]
Severity = Literal["info", "low", "medium", "high", "critical"]
AlertStatus = Literal["open", "in_progress", "resolved", "dismissed"]
RuleKind = Literal["match", "threshold", "cardinality", "sequence"]

assert set(Severity.__args__) == set(SEVERITIES)  # type: ignore[attr-defined]
assert set(AlertStatus.__args__) == set(ALERT_STATUSES)  # type: ignore[attr-defined]
assert set(RuleKind.__args__) == set(RULE_KINDS)  # type: ignore[attr-defined]


def to_naive_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------- auth
class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: str = Field(min_length=8, max_length=128)


class UserOut(ORM):
    id: int
    username: str
    role: str
    created_at: UTCDatetime


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


# --------------------------------------------------------------- events
_CORE_EVENT_FIELDS = {
    "timestamp", "source", "category", "action", "severity", "host", "username",
    "src_ip", "dst_ip", "dst_port", "message", "extra", "raw",
}


class EventIn(BaseModel):
    """An event as submitted by a shipper. Unknown top-level keys are folded into ``extra``."""

    model_config = ConfigDict(extra="allow")

    timestamp: datetime | None = None
    source: str = Field(default="api", max_length=64)
    category: str = Field(default="other", max_length=32)
    action: str = Field(default="log", max_length=64)
    severity: Severity = "info"
    host: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=128)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    message: str = Field(default="", max_length=4000)
    extra: dict[str, Any] = Field(default_factory=dict)
    raw: str | None = Field(default=None, max_length=8000)

    @model_validator(mode="before")
    @classmethod
    def _fold_unknown(cls, data: Any) -> Any:
        if isinstance(data, dict):
            unknown = {k: v for k, v in data.items() if k not in _CORE_EVENT_FIELDS}
            if unknown:
                data = {k: v for k, v in data.items() if k in _CORE_EVENT_FIELDS}
                data["extra"] = {**(data.get("extra") or {}), **unknown}
        return data

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime | None) -> datetime | None:
        return to_naive_utc(value)

    @field_validator("severity", mode="before")
    @classmethod
    def _lower(cls, value: Any) -> Any:
        return value.lower() if isinstance(value, str) else value


class EventOut(ORM):
    id: int
    timestamp: UTCDatetime
    ingested_at: UTCDatetime
    source: str
    category: str
    action: str
    severity: str
    host: str | None
    username: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    message: str
    extra: dict[str, Any]
    raw: str | None


class Page(BaseModel):
    total: int
    page: int
    page_size: int


class EventPage(Page):
    items: list[EventOut]


class RawIngest(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    host: str | None = Field(default=None, max_length=128)


class IngestResult(BaseModel):
    accepted: int
    alerts_created: int
    alerts_updated: int
    alert_ids: list[int]
    parsers: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------- rules
class RuleBase(BaseModel):
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=2000)
    severity: Severity = "medium"
    enabled: bool = True
    mitre_tactic: str | None = Field(default=None, max_length=64)
    mitre_technique: str | None = Field(default=None, max_length=32, pattern=r"^T\d{4}(\.\d{3})?$")


class RuleCreate(RuleBase):
    slug: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9\-]+$")
    kind: RuleKind
    definition: dict[str, Any]


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    severity: Severity | None = None
    enabled: bool | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = Field(default=None, pattern=r"^T\d{4}(\.\d{3})?$")
    definition: dict[str, Any] | None = None


class RuleOut(ORM):
    id: int
    slug: str
    name: str
    description: str
    kind: str
    severity: str
    enabled: bool
    builtin: bool
    mitre_tactic: str | None
    mitre_technique: str | None
    definition: dict[str, Any]
    created_at: UTCDatetime
    updated_at: UTCDatetime
    alert_count: int = 0


class RuleTestRequest(BaseModel):
    kind: RuleKind
    definition: dict[str, Any]
    lookback_minutes: int = Field(default=60, ge=1, le=60 * 24 * 7)


class RuleTestResult(BaseModel):
    events_scanned: int
    detections: list[dict[str, Any]]


# --------------------------------------------------------------- alerts
class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class NoteOut(ORM):
    id: int
    author: str
    body: str
    created_at: UTCDatetime


class AlertOut(ORM):
    id: int
    rule_id: int | None
    title: str
    summary: str
    severity: str
    status: str
    entity: str
    mitre_tactic: str | None
    mitre_technique: str | None
    hit_count: int
    event_ids: list[int] = Field(default_factory=list, exclude=True)
    first_seen: UTCDatetime
    last_seen: UTCDatetime
    assignee: str | None
    created_at: UTCDatetime
    updated_at: UTCDatetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def event_count(self) -> int:
        return len(self.event_ids)


class AlertDetail(AlertOut):
    events: list[EventOut] = Field(default_factory=list)
    notes: list[NoteOut] = Field(default_factory=list)
    rule: RuleOut | None = None


class AlertPage(Page):
    items: list[AlertOut]


class AlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assignee: str | None = Field(default=None, max_length=64)
    note: str | None = Field(default=None, max_length=4000)


class BulkAlertUpdate(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    status: AlertStatus


# ------------------------------------------------------------ simulator
class SimulationRequest(BaseModel):
    scenario: str
    attacker_ip: str | None = Field(default=None, max_length=64)
    target_host: str | None = Field(default=None, max_length=128)


class SimulationResult(IngestResult):
    scenario: str
    attacker_ip: str
    target_host: str


class NoiseRequest(BaseModel):
    enabled: bool
    events_per_second: float = Field(default=2.0, gt=0, le=50)
