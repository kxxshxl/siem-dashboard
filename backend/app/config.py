"""Runtime configuration, read from environment variables."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = field(
        default_factory=lambda: os.getenv("VIGIL_DATABASE_URL", "sqlite:///./vigil.db")
    )
    jwt_secret: str = field(
        default_factory=lambda: os.getenv("VIGIL_JWT_SECRET") or secrets.token_urlsafe(48)
    )
    jwt_ttl_minutes: int = field(
        default_factory=lambda: int(os.getenv("VIGIL_JWT_TTL_MINUTES", "720"))
    )
    # Optional shared secret that lets log shippers push events without a user login.
    ingest_token: str | None = field(default_factory=lambda: os.getenv("VIGIL_INGEST_TOKEN"))
    # How long an open alert keeps absorbing new detections for the same rule + entity.
    alert_dedup_minutes: int = field(
        default_factory=lambda: int(os.getenv("VIGIL_ALERT_DEDUP_MINUTES", "15"))
    )
    cors_origins: list[str] = field(
        default_factory=lambda: [
            o.strip()
            for o in os.getenv("VIGIL_CORS_ORIGINS", "http://localhost:5173").split(",")
            if o.strip()
        ]
    )
    allow_registration: bool = field(
        default_factory=lambda: _env_bool("VIGIL_ALLOW_REGISTRATION", True)
    )


settings = Settings()
