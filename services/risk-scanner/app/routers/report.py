from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_agent
from app.db import get_db
from app.models import ScanResult
from app.pdf_export import markdown_to_pdf

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _get_owned_scan(scan_id: str, request, db: Session) -> ScanResult:
    agent = get_current_agent(request, db)
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan or scan.assessment.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="Report not found")
    return scan


@router.get("/report/{scan_id}")
async def view_report(scan_id: str, request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    scan = _get_owned_scan(scan_id, request, db)
    return templates.TemplateResponse("report.html", {"request": request, "agent": agent, "scan": scan})


@router.get("/report/{scan_id}/client")
async def view_client_report(scan_id: str, request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    scan = _get_owned_scan(scan_id, request, db)
    return templates.TemplateResponse("client_report.html", {"request": request, "agent": agent, "scan": scan})


@router.get("/report/{scan_id}/pdf")
async def download_agent_pdf(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = _get_owned_scan(scan_id, request, db)
    if not scan.report_markdown:
        raise HTTPException(status_code=409, detail="Report not ready yet")
    pdf = markdown_to_pdf(scan.report_markdown, f"Underwriting-Bericht — {scan.assessment.company_name}")
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="underwriting-{scan_id}.pdf"'},
    )


@router.get("/report/{scan_id}/client/pdf")
async def download_client_pdf(scan_id: str, request: Request, db: Session = Depends(get_db)):
    scan = _get_owned_scan(scan_id, request, db)
    if not scan.client_report_markdown:
        raise HTTPException(status_code=409, detail="Report not ready yet")
    pdf = markdown_to_pdf(scan.client_report_markdown, f"Cyber-Sicherheitscheck — {scan.assessment.company_name}")
    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="sicherheitscheck-{scan_id}.pdf"'},
    )
