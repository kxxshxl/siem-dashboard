from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from ..config import settings
from ..deps import DB, CurrentUser
from ..models import User
from ..schemas import Credentials, TokenOut, UserOut
from ..security import create_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.get("/status")
def auth_status(db: DB) -> dict:
    has_users = (db.scalar(select(func.count(User.id))) or 0) > 0
    return {"has_users": has_users, "registration_open": settings.allow_registration or not has_users}


@router.post("/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(body: Credentials, db: DB) -> TokenOut:
    user_count = db.scalar(select(func.count(User.id))) or 0
    if user_count and not settings.allow_registration:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Registration is disabled")
    if db.scalars(select(User).where(User.username == body.username)).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken")
    # The first account bootstraps the deployment and becomes the administrator.
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role="admin" if user_count == 0 else "analyst",
    )
    db.add(user)
    db.commit()
    return TokenOut(access_token=create_token(user.username, user.role),
                    user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenOut)
def login(body: Credentials, db: DB) -> TokenOut:
    user = db.scalars(select(User).where(User.username == body.username)).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    return TokenOut(access_token=create_token(user.username, user.role),
                    user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: CurrentUser) -> User:
    return user
