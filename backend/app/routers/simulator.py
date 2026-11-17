from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import delete

from ..deps import DB, AdminUser, CurrentUser
from ..models import Alert, AlertNote, Event
from ..pipeline import detection_engine
from ..realtime import broadcaster
from ..schemas import IngestResult, NoiseRequest, SimulationRequest, SimulationResult
from ..simulator.environment import HOSTS
from ..simulator.noise import noise
from ..simulator.runner import backfill, run_scenario
from ..simulator.scenarios import SCENARIOS

router = APIRouter(prefix="/api/simulator", tags=["simulator"])


class BackfillRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    events_per_hour: int = Field(default=120, ge=10, le=2000)


@router.get("/scenarios")
def list_scenarios(_: CurrentUser) -> dict:
    return {
        "scenarios": [
            {
                "slug": s.slug,
                "name": s.name,
                "description": s.description,
                "tactics": s.tactics,
                "techniques": s.techniques,
                "default_target": s.default_target,
                "expected_rules": s.expected_rules,
            }
            for s in SCENARIOS.values()
        ],
        "hosts": [{"name": h.name, "ip": h.ip, "os": h.os, "role": h.role} for h in HOSTS],
    }


@router.post("/run", response_model=SimulationResult)
def run(body: SimulationRequest, db: DB, _: CurrentUser) -> SimulationResult:
    try:
        return run_scenario(db, body.scenario, body.attacker_ip, body.target_host)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown scenario") from exc


@router.get("/noise")
def noise_status(_: CurrentUser) -> dict:
    return {"enabled": noise.running, "events_per_second": noise.rate}


@router.post("/noise")
def set_noise(body: NoiseRequest, _: CurrentUser) -> dict:
    if body.enabled:
        noise.start(body.events_per_second)
    else:
        noise.stop()
    return {"enabled": noise.running, "events_per_second": noise.rate}


@router.post("/backfill", response_model=IngestResult)
def run_backfill(body: BackfillRequest, db: DB, _: CurrentUser) -> IngestResult:
    return backfill(db, body.hours, body.events_per_hour)


@router.delete("/data", status_code=status.HTTP_204_NO_CONTENT)
def purge(db: DB, _: AdminUser) -> None:
    """Wipe all events and alerts (rules and users are kept)."""
    db.execute(delete(AlertNote))
    db.execute(delete(Alert))
    db.execute(delete(Event))
    db.commit()
    detection_engine.clear_state()
    broadcaster.publish("purged", {})
