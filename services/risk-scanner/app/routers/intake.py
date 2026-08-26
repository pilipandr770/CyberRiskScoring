import ipaddress
import logging
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_agent
from app.db import SessionLocal, get_db
from app.models import AgentUser, ClientAssessment, ScanResult
from app.scoring.pipeline import run_scan
from app.security import get_csrf_token, verify_csrf

log = logging.getLogger("intake")

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
        "intake_form.html",
        {
            "request": request, "agent": agent, "industries": INDUSTRIES, "error": None,
            "csrf_token": get_csrf_token(request),
        },
    )


def _validate_office_ip(raw: str) -> str | None:
    """None means valid (or empty — Tier 1 is optional). Anything else is a
    user-facing error message. Catches non-IP input (e.g. a street address
    pasted into the wrong field) before it burns minutes on a doomed nmap
    scan against an unresolvable "host" — this is exactly what happened in
    production once already."""
    raw = raw.strip()
    if not raw:
        return None
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            ipaddress.ip_network(token, strict=False)
        except ValueError:
            return f'"{token}" ist keine gültige IP-Adresse oder kein gültiger IP-Bereich (z.B. 203.0.113.5 oder 203.0.113.0/24).'
    return None


async def _run_scan_background(scan_id: str, assessment_id: int) -> None:
    """Runs after the HTTP response is already sent (FastAPI BackgroundTasks)
    — a Tier 1 scan (nmap/Shodan/nuclei/2 LLM calls) can easily take minutes,
    which reliably exceeded Cloudflare's ~100s gateway timeout when this ran
    inline in the request, showing the agent a 524 error page even though
    the scan itself completed fine server-side. Uses its own DB session
    since the request-scoped one closes as soon as the response is sent."""
    db = SessionLocal()
    try:
        assessment = db.query(ClientAssessment).filter(ClientAssessment.id == assessment_id).first()
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        try:
            result = await run_scan(assessment)
            for key, value in result.items():
                setattr(scan, key, value)
            scan.status = "done"
            scan.finished_at = datetime.utcnow()
        except Exception as exc:
            log.exception("Scan %s failed", scan_id)
            scan.status = "error"
            scan.error_message = str(exc)
        db.commit()
    finally:
        db.close()


@router.post("/intake/new")
async def intake_submit(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    csrf_token: str = Form(...),
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
    verify_csrf(request, csrf_token)

    if consent_confirmed != "yes":
        return templates.TemplateResponse(
            "intake_form.html",
            {
                "request": request, "agent": agent, "industries": INDUSTRIES,
                "error": "Ohne bestätigte schriftliche Zustimmung des Kunden kann kein Scan gestartet werden.",
                "csrf_token": get_csrf_token(request),
            },
        )

    ip_error = _validate_office_ip(office_ip)
    if ip_error:
        return templates.TemplateResponse(
            "intake_form.html",
            {
                "request": request, "agent": agent, "industries": INDUSTRIES,
                "error": f"Büro-IP-Adresse: {ip_error}",
                "csrf_token": get_csrf_token(request),
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

    # Runs after this response is sent — see _run_scan_background's
    # docstring for why this can't be a plain `await` here.
    background_tasks.add_task(_run_scan_background, scan.id, assessment.id)

    return RedirectResponse(url=f"/report/{scan.id}", status_code=303)
