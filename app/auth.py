from dataclasses import dataclass
from typing import Optional

import bcrypt
from fastapi import Request
from sqlmodel import Session, select

from app.config import AUTH_DISABLED
from app.database import engine
from app.models import User


@dataclass
class AnonymousUser:
    """Stand-in for the logged-in user when HOMELAB_DECK_DISABLE_AUTH is set."""

    id: None = None
    username: str = "local"


ANONYMOUS_USER = AnonymousUser()


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def any_user_exists() -> bool:
    with Session(engine) as session:
        return session.exec(select(User)).first() is not None


def get_user_by_username(username: str) -> Optional[User]:
    with Session(engine) as session:
        return session.exec(select(User).where(User.username == username)).first()


def create_user(username: str, password: str) -> User:
    with Session(engine) as session:
        user = User(username=username, password_hash=hash_password(password))
        session.add(user)
        session.commit()
        session.refresh(user)
        return user


def current_user(request: Request) -> Optional[User]:
    if AUTH_DISABLED:
        return ANONYMOUS_USER
    user_id = request.session.get("user_id")
    if user_id is None:
        return None
    with Session(engine) as session:
        return session.get(User, user_id)
