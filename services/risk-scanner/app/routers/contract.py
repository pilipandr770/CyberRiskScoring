from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth import get_current_agent
from app.db import get_db
from app.models import ScanResult
from app.pdf_export import markdown_to_pdf
from app.scoring import risk_formula
from app.scoring.contract_document import render_contract_markdown
from app.scoring.insurance_document import check_obliegenheiten, default_contract_fields
from app.security import get_csrf_token, verify_csrf

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


def _get_owned_scan(scan_id: str, request: Request, db: Session) -> ScanResult:
    agent = get_current_agent(request, db)
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan or scan.assessment.agent_id != agent.id:
        raise HTTPException(status_code=404, detail="Report not found")
    return scan


def _scan_findings(scan: ScanResult) -> list[dict]:
    import json
    if not scan.raw_findings_json:
        return []
    return json.loads(scan.raw_findings_json).get("findings", [])


@router.get("/report/{scan_id}/contract")
async def contract_form(scan_id: str, request: Request, db: Session = Depends(get_db)):
    agent = get_current_agent(request, db)
    scan = _get_owned_scan(scan_id, request, db)
    if scan.status != "done":
        raise HTTPException(status_code=409, detail="Scan not finished yet")

    assessment = scan.assessment
    ransom = risk_formula.ransom_exposure(assessment.annual_turnover_eur)
    fields = default_contract_fields(
        assessment=assessment,
        scan={
            "expected_damage_eur": scan.expected_damage_eur,
            "premium_range_low_eur": scan.premium_range_low_eur,
            "premium_range_high_eur": scan.premium_range_high_eur,
        },
        ransom=ransom,
    )
    obliegenheiten = check_obliegenheiten(assessment=assessment, findings=_scan_findings(scan))

    return templates.TemplateResponse(
        "contract_form.html",
        {
            "request": request, "agent": agent, "scan": scan, "fields": fields, "obliegenheiten": obliegenheiten,
            "csrf_token": get_csrf_token(request),
        },
    )


@router.post("/report/{scan_id}/contract/pdf")
async def generate_contract_pdf(
    scan_id: str, request: Request, db: Session = Depends(get_db),
    csrf_token: str = Form(...),
    insurer_name: str = Form(...),
    policy_start: str = Form(...),
    policy_term_years: int = Form(1),
    sum_a2: float = Form(...),
    sum_a3: float = Form(...),
    sum_a4_1: float = Form(...),
    sum_a4_2: float = Form(...),
    sum_extortion: float = Form(...),
    total_sum: float = Form(...),
    haftzeit_bu_months: int = Form(3),
    wartezeit_bu_hours: int = Form(12),
    deductible_eur: float = Form(...),
    premium_annual_eur: float = Form(...),
    payment_frequency: str = Form("jährlich"),
):
    scan = _get_owned_scan(scan_id, request, db)
    verify_csrf(request, csrf_token)
    assessment = scan.assessment

    fields = {
        "policyholder_name": assessment.company_name,
        "policyholder_hrb": assessment.hrb_number or "",
        "policyholder_domain": assessment.domain,
        "insurer_name_placeholder": insurer_name,
        "policy_start_placeholder": policy_start,
        "policy_term_years": policy_term_years,
        "total_sum_insured_eur": total_sum,
        "sums": {
            "a2_forensik_kosten": sum_a2,
            "a3_drittschaden": sum_a3,
            "a4_1_betriebsunterbrechung": sum_a4_1,
            "a4_2_datenwiederherstellung": sum_a4_2,
            "cyber_erpressung": sum_extortion,
        },
        "haftzeit_bu_months": haftzeit_bu_months,
        "wartezeit_bu_hours": wartezeit_bu_hours,
        "deductible_eur": deductible_eur,
        "premium_annual_eur": premium_annual_eur,
        "payment_frequency": payment_frequency,
        "avb_reference": "AVB Cyber (GDV-Musterbedingungen, Stand Februar 2024)",
    }
    obliegenheiten = check_obliegenheiten(assessment=assessment, findings=_scan_findings(scan))

    md = render_contract_markdown(fields=fields, obliegenheiten=obliegenheiten, industry=assessment.industry, tier=scan.tier)
    pdf = markdown_to_pdf(md, f"Versicherungsantrag — {assessment.company_name}")

    return Response(
        content=pdf, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="versicherungsantrag-{scan_id}.pdf"'},
    )
