from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_agent
from app.db import get_db
from app.m3_provisioning import provision
from app.models import ScanResult
from app.security import get_csrf_token, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _get_owned_scan(scan_id: str, request: Request, db: Session) -> ScanResult:
    agent = get_current_agent(request, db)
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan or scan.assessment.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="Report not found")
    return scan


@router.get("/report/{scan_id}/decision")
async def decision_form(scan_id: str, request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    scan = _get_owned_scan(scan_id, request, db)
    return templates.TemplateResponse(
        "decision_form.html",
        {"request": request, "agent": agent, "scan": scan, "csrf_token": get_csrf_token(request)},
    )


@router.post("/report/{scan_id}/decision")
async def submit_decision(
    scan_id: str, request: Request, db: Session = Depends(get_db),
    csrf_token: str = Form(...),
    decision: str = Form(...),           # accepted / adjusted / rejected
    final_premium_eur: str = Form(""),
    notes: str = Form(""),
):
    agent = get_current_agent(request, db)
    scan = _get_owned_scan(scan_id, request, db)
    verify_csrf(request, csrf_token)

    scan.decision_status = decision
    scan.decision_notes = notes or None
    scan.decided_by = agent.id
    scan.decided_at = datetime.utcnow()

    if decision in ("accepted", "adjusted"):
        try:
            scan.decision_premium_eur = float(final_premium_eur) if final_premium_eur else scan.premium_range_low_eur
        except ValueError:
            scan.decision_premium_eur = scan.premium_range_low_eur
    db.commit()

    if decision == "accepted":
        result = await provision(assessment=scan.assessment, scan=scan)
        scan.m3_provisioned = "yes" if result["status"] == "ok" else ("failed" if result["status"] == "failed" else "no")
        scan.m3_provisioned_at = datetime.utcnow() if result["status"] == "ok" else None
        scan.m3_provision_error = result.get("reason")
        db.commit()

    return RedirectResponse(url=f"/report/{scan_id}/decision", status_code=303)
