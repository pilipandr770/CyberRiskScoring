"""
Machine API for Module 3 (nis2.store) — replaces the old external "black
box" pentesting microservice. Same contract their existing
microservice_client.py already calls (POST /api/audit, GET /api/audit/{id},
.../findings) so integrating this is a URL swap on their side, not a
rewrite: only api_export.py's translation layer bridges the shapes.

Auth: a static API key (X-API-Key header) — separate from the agent's
session-cookie auth used everywhere else in this app. Machine-to-machine,
not a browser session.
"""

import asyncio
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api_export import to_microservice_findings
from app.config import M3_API_KEY
from app.db import get_db
from app.models import ClientAssessment, ScanResult
from app.scoring.pipeline import run_scan

router = APIRouter(prefix="/api")


def _require_api_key(x_api_key: str = Header(default="")) -> None:
    if not M3_API_KEY:
        raise HTTPException(status_code=503, detail="Machine API not configured (M3_API_KEY unset)")
    if x_api_key != M3_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


class AuditRequest(BaseModel):
    target: str
    company: str


def _system_agent_id(db: Session) -> str:
    from app.models import AgentUser
    from app.auth import hash_password
    agent = db.query(AgentUser).filter(AgentUser.username == "api-service").first()
    if not agent:
        import secrets
        agent = AgentUser(username="api-service", password_hash=hash_password(secrets.token_hex(32)),
                           display_name="API Service Account")
        db.add(agent)
        db.commit()
        db.refresh(agent)
    return agent.id


async def _run_scan_background(assessment_id: str):
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        assessment = db.query(ClientAssessment).filter(ClientAssessment.id == assessment_id).first()
        scan = db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).first()
        scan.status = "running"
        db.commit()
        try:
            result = await run_scan(assessment)
            for key, value in result.items():
                setattr(scan, key, value)
            scan.status = "done"
            scan.finished_at = datetime.utcnow()
        except Exception as exc:
            scan.status = "error"
            scan.error_message = str(exc)
        db.commit()
    finally:
        db.close()


@router.get("/health")
def health():
    return {"ok": True}


@router.post("/audit", dependencies=[Depends(_require_api_key)])
async def start_audit(body: AuditRequest, db: Session = Depends(get_db)):
    agent_id = _system_agent_id(db)
    assessment = ClientAssessment(
        agent_id=agent_id,
        company_name=body.company,
        domain=body.target.replace("https://", "").replace("http://", "").rstrip("/"),
        industry="other",
        consent_confirmed="yes",  # M3 only calls this for already-onboarded, consented clients
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    scan = ScanResult(assessment_id=assessment.id, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    asyncio.create_task(_run_scan_background(assessment.id))

    return {"job_id": scan.id}


@router.get("/audit/{job_id}", dependencies=[Depends(_require_api_key)])
def audit_status(job_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == job_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    status_map = {"pending": "pending", "running": "running", "done": "done", "error": "failed"}
    findings_count = 0
    if scan.raw_findings_json:
        findings_count = len(json.loads(scan.raw_findings_json).get("findings", []))
    return {"status": status_map.get(scan.status, "running"), "findings_count": findings_count}


@router.get("/audit/{job_id}/findings", dependencies=[Depends(_require_api_key)])
def audit_findings(job_id: str, db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == job_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Unknown job_id")
    findings = []
    if scan.raw_findings_json:
        findings = json.loads(scan.raw_findings_json).get("findings", [])
    return {"findings": to_microservice_findings(findings)}


@router.get("/audit/{job_id}/logs", dependencies=[Depends(_require_api_key)])
def audit_logs(job_id: str, after: int = 0):
    # No structured log stream yet — their client already treats log-fetch
    # failures/empty results as non-critical, so an empty list is enough.
    return {"logs": []}
