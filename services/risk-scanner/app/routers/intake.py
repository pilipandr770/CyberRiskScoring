from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_agent
from app.db import get_db
from app.models import AgentUser, ClientAssessment, ScanResult
from app.scoring.pipeline import run_scan

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

INDUSTRIES = [
    ("retail", "Einzelhandel / Retail"),
    ("healthcare", "Gesundheitswesen"),
    ("finance", "Finanzdienstleistungen"),
    ("manufacturing", "Produktion / Manufacturing"),
    ("it_software", "IT / Software"),
    ("logistics", "Logistik"),
    ("other", "Sonstige"),
]


@router.get("/")
async def dashboard(request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    assessments = (
        db.query(ClientAssessment)
        .filter(ClientAssessment.agent_id == agent.id)
        .order_by(ClientAssessment.created_at.desc())
        .all()
    )
    latest_scan_by_assessment = {}
    for a in assessments:
        scan = (
            db.query(ScanResult)
            .filter(ScanResult.assessment_id == a.id)
            .order_by(ScanResult.created_at.desc())
            .first()
        )
        latest_scan_by_assessment[a.id] = scan
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "agent": agent, "assessments": assessments, "scans": latest_scan_by_assessment},
    )


@router.get("/intake/new")
async def intake_form(request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    return templates.TemplateResponse(
        "intake_form.html", {"request": request, "agent": agent, "industries": INDUSTRIES, "error": None}
    )


@router.post("/intake/new")
async def intake_submit(
    request: Request,
    db: Session = Depends(get_db),
    company_name: str = Form(...),
    hrb_number: str = Form(""),
    contact_email: str = Form(""),
    domain: str = Form(...),
    industry: str = Form(...),
    employee_band: str = Form(""),
    annual_turnover_eur: str = Form(""),
    office_ip: str = Form(""),
    prior_incident: str = Form("no"),
    prior_incident_notes: str = Form(""),
    has_mfa: str = Form("unknown"),
    has_tested_backups: str = Form("unknown"),
    existing_cyber_insurance: str = Form("no"),
    consent_confirmed: str = Form(""),
):
    agent = get_current_agent(request, db)

    if consent_confirmed != "yes":
        return templates.TemplateResponse(
            "intake_form.html",
            {
                "request": request, "agent": agent, "industries": INDUSTRIES,
                "error": "Ohne bestätigte schriftliche Zustimmung des Kunden kann kein Scan gestartet werden.",
            },
        )

    turnover = None
    if annual_turnover_eur.strip():
        try:
            turnover = float(annual_turnover_eur.replace(".", "").replace(",", "."))
        except ValueError:
            turnover = None

    assessment = ClientAssessment(
        agent_id=agent.id,
        company_name=company_name.strip(),
        hrb_number=hrb_number.strip() or None,
        contact_email=contact_email.strip().lower() or None,
        domain=domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/"),
        industry=industry,
        employee_band=employee_band or None,
        annual_turnover_eur=turnover,
        office_ip=office_ip.strip() or None,
        prior_incident=prior_incident,
        prior_incident_notes=prior_incident_notes or None,
        has_mfa=has_mfa,
        has_tested_backups=has_tested_backups,
        existing_cyber_insurance=existing_cyber_insurance,
        consent_confirmed="yes",
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    scan = ScanResult(assessment_id=assessment.id, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

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

    return RedirectResponse(url=f"/report/{scan.id}", status_code=303)
