"""FastAPI application entrypoint."""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text

from . import __version__
from .config import settings
from .database import SessionLocal, init_db
from .deps import user_from_token
from .detection.loader import reload_engine, seed_default_rules
from .models import Event
from .pipeline import detection_engine
from .realtime import broadcaster
from .routers import alerts, auth, events, rules, simulator, stats
from .simulator.noise import noise
from .simulator.runner import backfill

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vigil")


def bootstrap() -> None:
    init_db()
    with SessionLocal() as db:
        added = seed_default_rules(db)
        if added:
            log.info("seeded %d built-in detection rules", added)
        reload_engine(db, detection_engine)
        log.info("detection engine loaded %d enabled rules", len(detection_engine.rules))

        demo_hours = int(os.getenv("VIGIL_DEMO_BACKFILL_HOURS", "0"))
        if demo_hours and not db.scalar(select(func.count(Event.id))):
            result = backfill(db, demo_hours)
            log.info("demo backfill: %d events, %d alerts", result.accepted, result.alerts_created)


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap()
    await broadcaster.start()
    noise_rate = float(os.getenv("VIGIL_NOISE_EPS", "0"))
    if noise_rate > 0:
        noise.start(noise_rate)
    yield
    noise.stop()
    await broadcaster.stop()


app = FastAPI(
    title="Vigil SIEM",
    version=__version__,
    description="Log ingestion, real-time correlation and alert triage.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

for module in (auth, events, alerts, rules, simulator, stats):
    app.include_router(module.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    with SessionLocal() as db:
        db.execute(text("SELECT 1"))
    return {"status": "ok", "version": __version__, "rules": len(detection_engine.rules)}


@app.websocket("/api/ws")
async def live_feed(ws: WebSocket) -> None:
    """Live stream of events and alerts.

    Browsers can't set headers on WebSockets, and a token in the URL would end up in
    access logs, so the client must send its JWT as the first message.
    """
    await ws.accept()
    try:
        token = await asyncio.wait_for(ws.receive_text(), timeout=5)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await ws.close(code=4401)
        return
    with SessionLocal() as db:
        user = user_from_token(db, token.strip())
    if user is None:
        await ws.close(code=4401)
        return
    await broadcaster.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive pings from the client; content ignored
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.disconnect(ws)
