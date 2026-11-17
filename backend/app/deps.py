"""Shared FastAPI dependencies: authentication and authorization."""

from __future__ import annotations

import hmac
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User
from .security import decode_token

DB = Annotated[Session, Depends(get_db)]
_bearer = HTTPBearer(auto_error=False)


def user_from_token(db: Session, token: str) -> User | None:
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        return None
    return db.scalars(select(User).where(User.username == payload.get("sub"))).first()


def current_user(
    db: DB, creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)]
) -> User:
    user = user_from_token(db, creds.credentials) if creds else None
    if user is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def admin_user(user: CurrentUser) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin role required")
    return user


AdminUser = Annotated[User, Depends(admin_user)]


def ingest_principal(
    db: DB,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    x_ingest_token: Annotated[str | None, Header()] = None,
) -> str:
    """Log shippers may authenticate with a static ingest token instead of a user JWT."""
    if x_ingest_token and settings.ingest_token and hmac.compare_digest(
        x_ingest_token, settings.ingest_token
    ):
        return "ingest-token"
    user = user_from_token(db, creds.credentials) if creds else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Valid JWT or X-Ingest-Token required")
    return user.username


IngestPrincipal = Annotated[str, Depends(ingest_principal)]
