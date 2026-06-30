from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.auth import (
    any_user_exists,
    create_user,
    current_user,
    get_user_by_username,
    hash_password,
    verify_password,
)
from app.database import engine
from app.models import User
from app.templating import templates

router = APIRouter()


@router.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    if any_user_exists():
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", {"error": None})


@router.post("/setup", response_class=HTMLResponse)
def setup_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
):
    if any_user_exists():
        return RedirectResponse("/login", status_code=303)
    if not username.strip() or not password:
        return templates.TemplateResponse(
            request, "setup.html", {"error": "Username and password are required."}
        )
    if password != password_confirm:
        return templates.TemplateResponse(
            request, "setup.html", {"error": "Passwords do not match."}
        )
    user = create_user(username.strip(), password)
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if not any_user_exists():
        return RedirectResponse("/setup", status_code=303)
    if current_user(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user_by_username(username.strip())
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid username or password."}
        )
    request.session["user_id"] = user.id
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.post("/settings/users/password")
def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
):
    user = current_user(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not verify_password(current_password, user.password_hash):
        return RedirectResponse("/settings?error=Current+password+is+incorrect", status_code=303)
    if new_password != new_password_confirm:
        return RedirectResponse("/settings?error=New+passwords+do+not+match", status_code=303)
    with Session(engine) as session:
        db_user = session.get(User, user.id)
        db_user.password_hash = hash_password(new_password)
        session.add(db_user)
        session.commit()
    return RedirectResponse("/settings?ok=Password+updated", status_code=303)


@router.post("/settings/users/add")
def add_user(request: Request, username: str = Form(...), password: str = Form(...)):
    if current_user(request) is None:
        return RedirectResponse("/login", status_code=303)
    if get_user_by_username(username.strip()):
        return RedirectResponse("/settings?error=Username+already+exists", status_code=303)
    create_user(username.strip(), password)
    return RedirectResponse("/settings?ok=User+added", status_code=303)


@router.post("/settings/users/{user_id}/delete")
def delete_user(request: Request, user_id: int):
    requester = current_user(request)
    if requester is None:
        return RedirectResponse("/login", status_code=303)
    with Session(engine) as session:
        total = len(session.exec(select(User)).all())
        if total <= 1:
            return RedirectResponse("/settings?error=Cannot+delete+the+only+user", status_code=303)
        target = session.get(User, user_id)
        if target:
            session.delete(target)
            session.commit()
    if requester.id == user_id:
        request.session.clear()
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/settings?ok=User+deleted", status_code=303)
