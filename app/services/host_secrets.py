"""Passwords for command hosts that sign in with a password instead of an SSH key.

They live in the database, not in commands.yml, so they are not in that file's download or
history. They are stored the way uploaded SSH keys are (readable by whoever can read ulmo's
data volume), and are only ever handed to ssh through an environment variable, never an argument.
"""
from sqlmodel import Session, delete, select

from app.database import engine
from app.models import HostPassword

MAX_LENGTH = 256


def check(password: str) -> str:
    if not password:
        raise ValueError("Enter the password for this host.")
    if len(password) > MAX_LENGTH or "\0" in password or "\n" in password or "\r" in password:
        raise ValueError(f"The password must be one line of at most {MAX_LENGTH} characters.")
    return password


def set_password(host: str, password: str) -> None:
    check(password)
    with Session(engine) as session:
        session.merge(HostPassword(host=host, password=password))
        session.commit()


def get(host: str) -> str | None:
    with Session(engine) as session:
        row = session.get(HostPassword, host)
    return row.password if row else None


def clear(host: str) -> None:
    with Session(engine) as session:
        session.exec(delete(HostPassword).where(HostPassword.host == host))
        session.commit()


def hosts_with_password() -> set[str]:
    with Session(engine) as session:
        return set(session.exec(select(HostPassword.host)).all())
