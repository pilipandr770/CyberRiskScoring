"""
Provisions the client's account on Module 3 (nis2.store) once an
underwriter accepts a decision — that acceptance is the actual "policy
issued" event; nothing else in this system marked that before. If
M3_PROVISIONING_WEBHOOK_URL isn't configured, the decision is still
recorded — provisioning is just logged as skipped rather than failing the
whole decision (M3 integration is real but independently deployed; this
app must not become unusable if that endpoint is down or not yet set up).
"""

import json
import logging

import httpx

from app.api_export import to_microservice_findings
from app.config import M3_PROVISIONING_API_KEY, M3_PROVISIONING_WEBHOOK_URL

log = logging.getLogger("m3_provisioning")


async def provision(*, assessment, scan) -> dict:
    if not M3_PROVISIONING_WEBHOOK_URL:
        log.info("M3 provisioning skipped (no webhook configured) for %s", assessment.company_name)
        return {"status": "skipped", "reason": "M3_PROVISIONING_WEBHOOK_URL not configured"}

    findings = []
    if scan.raw_findings_json:
        findings = json.loads(scan.raw_findings_json).get("findings", [])

    # Translated to the same title/severity/cvss/dsgvo_article/recommendation
    # shape used everywhere else M1 data crosses into M3 (see api_export.py)
    # — one finding shape for the whole handoff, not a second bespoke one.
    baseline_findings = to_microservice_findings(findings)

    payload = {
        "company_name": assessment.company_name,
        "hrb_number": assessment.hrb_number,
        "domain": assessment.domain,
        "industry": assessment.industry,
        "contact_email": assessment.contact_email,
        "baseline_findings": baseline_findings,
        "baseline_risk_tier": scan.risk_tier,
        "policy_premium_eur": scan.decision_premium_eur,
        "scan_id": scan.id,
    }

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                M3_PROVISIONING_WEBHOOK_URL,
                json=payload,
                headers={"X-API-Key": M3_PROVISIONING_API_KEY} if M3_PROVISIONING_API_KEY else {},
            )
            resp.raise_for_status()
        return {"status": "ok"}
    except Exception as exc:
        log.warning("M3 provisioning failed for %s: %s", assessment.company_name, exc)
        return {"status": "failed", "reason": str(exc)}
