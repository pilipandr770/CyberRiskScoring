from passlib.context import CryptContext
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session

from app.models import AgentUser

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(raw: str) -> str:
    return _pwd_ctx.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    return _pwd_ctx.verify(raw, hashed)


def get_current_agent(request: Request, db: Session) -> AgentUser:
    agent_id = request.session.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    agent = db.query(AgentUser).filter(AgentUser.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return agent
