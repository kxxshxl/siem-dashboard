"""Bridges database rules and the in-memory detection engine."""

from __future__ import annotations

from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Rule
from .engine import CompiledRule, DetectionEngine, validate_definition

DEFAULT_RULES_PATH = Path(__file__).with_name("default_rules.yml")


def compile_rule(rule: Rule) -> CompiledRule:
    return CompiledRule(
        id=rule.id,
        slug=rule.slug,
        name=rule.name,
        kind=rule.kind,
        severity=rule.severity,
        definition=rule.definition or {},
        mitre_tactic=rule.mitre_tactic,
        mitre_technique=rule.mitre_technique,
    )


def seed_default_rules(db: Session, path: Path = DEFAULT_RULES_PATH) -> int:
    """Insert built-in rules that are not in the database yet. Returns number added."""
    specs = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    existing = set(db.scalars(select(Rule.slug)))
    added = 0
    for spec in specs:
        if spec["slug"] in existing:
            continue
        validate_definition(spec["kind"], spec["definition"])
        db.add(Rule(builtin=True, enabled=spec.pop("enabled", True), **spec))
        added += 1
    db.commit()
    return added


def reload_engine(db: Session, engine: DetectionEngine) -> None:
    rules = db.scalars(select(Rule).where(Rule.enabled.is_(True)).order_by(Rule.id))
    engine.load(compile_rule(r) for r in rules)
