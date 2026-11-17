"""Database models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp. All datetimes are stored as naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}

ALERT_STATUSES = ("open", "in_progress", "resolved", "dismissed")
RULE_KINDS = ("match", "threshold", "cardinality", "sequence")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(64), index=True)  # sshd, firewall, edr, web ...
    category: Mapped[str] = mapped_column(String(32), index=True)  # authentication, network ...
    action: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    host: Mapped[str | None] = mapped_column(String(128), index=True)
    username: Mapped[str | None] = mapped_column(String(128), index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text, default="")
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[str | None] = mapped_column(Text)

    def as_detection_record(self) -> dict:
        """Flat dict view of the event used by the detection engine."""
        record = dict(self.extra or {})
        record.update(
            id=self.id,
            timestamp=self.timestamp,
            source=self.source,
            category=self.category,
            action=self.action,
            severity=self.severity,
            host=self.host,
            username=self.username,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            message=self.message,
        )
        return record


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text, default="")
    kind: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))
    mitre_technique: Mapped[str | None] = mapped_column(String(32))
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alert_rule_entity", "rule_id", "entity", "status"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("rules.id", ondelete="SET NULL"))
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    entity: Mapped[str] = mapped_column(String(200), default="")  # grouping key, e.g. src_ip=1.2.3.4
    mitre_tactic: Mapped[str | None] = mapped_column(String(64))
    mitre_technique: Mapped[str | None] = mapped_column(String(32))
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    assignee: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    rule: Mapped[Rule | None] = relationship(lazy="joined")
    notes: Mapped[list["AlertNote"]] = relationship(
        back_populates="alert", cascade="all, delete-orphan", order_by="AlertNote.created_at"
    )


class AlertNote(Base):
    __tablename__ = "alert_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    author: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    alert: Mapped[Alert] = relationship(back_populates="notes")
