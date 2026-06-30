from fastapi import HTTPException, Request

from app.auth import current_user


def require_login(request: Request):
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user
