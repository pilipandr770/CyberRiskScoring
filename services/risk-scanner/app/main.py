import asyncio
import logging

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import SESSION_SECRET
from app.db import init_db
from app.routers import api, auth, contract, decision, intake, report
from app.scoring import cve_dataset

logging.basicConfig(level=logging.INFO)

app = FastAPI(title="CyberVersiecherung — Risk Scanner (Module 1 MVP)")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

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
