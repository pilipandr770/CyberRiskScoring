import asyncio
import logging

from fastapi import FastAPI, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import SESSION_COOKIE_SECURE, SESSION_MAX_AGE_SECONDS, SESSION_SECRET
from app.db import init_db
from app.rate_limit import limiter
from app.routers import api, auth, contract, decision, intake, report
from app.scoring import cve_dataset

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="CyberVersiecherung — Risk Scanner (Module 1 MVP)")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=SESSION_COOKIE_SECURE,
    same_site="lax",
    max_age=SESSION_MAX_AGE_SECONDS,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if SESSION_COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response

app.include_router(auth.router)
app.include_router(intake.router)
app.include_router(report.router)
app.include_router(contract.router)
app.include_router(decision.router)
app.include_router(api.router)


@app.on_event("startup")
async def _startup():
    init_db()
    # Runs in the background — the CVE cache populates in a thread executor
    # so it doesn't block server startup or request handling. Until it's
    # ready, cve_dataset.match() just returns no hits (graceful fallback).
    asyncio.create_task(cve_dataset.refresh_if_stale())


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/cve-cache")
def cve_cache_health():
    return cve_dataset.cache_status()
