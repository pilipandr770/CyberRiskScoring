from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import verify_password
from app.config import LOGIN_RATE_LIMIT
from app.db import get_db
from app.models import AgentUser
from app.rate_limit import limiter
from app.security import get_csrf_token, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/login")
async def login_form(request: Request):
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": None, "csrf_token": get_csrf_token(request)}
    )


@router.post("/login")
@limiter.limit(LOGIN_RATE_LIMIT)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    agent = db.query(AgentUser).filter(AgentUser.username == username).first()
    if not agent or not verify_password(password, agent.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Falscher Benutzername oder Passwort.",
                "csrf_token": get_csrf_token(request),
            },
        )
    request.session["agent_id"] = agent.id
    request.session["agent_name"] = agent.display_name or agent.username
    return RedirectResponse(url="/", status_code=303)


@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
