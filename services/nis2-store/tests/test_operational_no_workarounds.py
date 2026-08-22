from datetime import UTC, datetime

from app.extensions import db
from app.models import User
from app.nis2.models import (
    BSIRegistration,
    ISMSInterview,
    ITAsset,
    MonitoringScan,
    MonitoringTarget,
    NIS2AuditJob,
    NIS2AuditTask,
    ProcessingActivity,
    Risk,
    SecurityTraining,
    Supplier,
    TrainingAcknowledgment,
)


def _register(client, email: str, password: str = "Secret123!"):
    resp = client.post(
        "/auth/register",
        data={
            "email": email,
            "password": password,
            "password2": password,
            "company_name": "Ops GmbH",
            "first_name": "Ops",
            "last_name": "Tester",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    assert "/nis2/" in resp.headers["Location"]


def test_operational_routes_work_without_db_hacks(flask_app, client, monkeypatch):
    _register(client, "ops@example.com")

    # Dashboard and static paid page.
    assert client.get("/nis2/").status_code == 200
    assert client.get("/payments/pricing").status_code == 200

    # Public BSI affectedness check + full wizard/export cycle.
    check_resp = client.post(
        "/nis2/bsi-registration/check",
        data={"sector": "digital_cloud", "employees": "50to249", "revenue": "10to50"},
    )
    assert check_resp.status_code == 200

    start_resp = client.post("/nis2/bsi-registration/wizard/start", follow_redirects=False)
    assert start_resp.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        assert user is not None
        reg = BSIRegistration.query.filter_by(user_id=user.id).first()
        assert reg is not None
        reg_id = reg.id

    for step, payload in [
        (1, {"company_name": "Ops GmbH", "legal_form": "GmbH", "employee_count": "120", "annual_revenue_eur": "15000000"}),
        (2, {"sector": "digital_cloud", "subsector": "Cloud"}),
        (3, {"gf_name": "Max GF", "gf_email": "gf@example.com", "ciso_name": "Alice CISO", "ciso_email": "ciso@example.com"}),
        (4, {"ip_ranges": "203.0.113.0/24", "domains": "ops.example", "cloud_providers": "AWS", "it_services": "SOC", "employee_count_it": "5"}),
        (5, {"confirm": "1"}),
    ]:
        resp = client.post(f"/nis2/bsi-registration/wizard/{reg_id}/step/{step}", data=payload, follow_redirects=False)
        assert resp.status_code == 302

    assert client.get(f"/nis2/bsi-registration/{reg_id}/export").status_code == 200
    assert client.get(f"/nis2/bsi-registration/{reg_id}/export/json").status_code == 200

    # ISMS interview flow + deterministic document generation (no external AI dependency).
    isms_start = client.post("/nis2/isms/interview/start", data={"company_name": "Ops GmbH"}, follow_redirects=False)
    assert isms_start.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        interview = ISMSInterview.query.filter_by(user_id=user.id).first()
        assert interview is not None
        interview_id = interview.id

    for phase in [1, 2, 3]:
        resp = client.post(f"/nis2/isms/interview/{interview_id}/phase/{phase}", data={}, follow_redirects=False)
        assert resp.status_code == 302

    resp = client.post(
        f"/nis2/isms/interview/{interview_id}/phase/4",
        data={"documents_to_generate": ["security_policy|Sicherheitsleitlinie"]},
        follow_redirects=False,
    )
    assert resp.status_code == 302

    assert client.get(f"/nis2/isms/interview/{interview_id}/review").status_code == 200
    gen_list = client.post(f"/nis2/isms/interview/{interview_id}/generate")
    assert gen_list.status_code == 200

    def _fake_generate_document(self, doc_type_key, all_data):
        return (f"# Auto {doc_type_key}\n\nGenerated for testing.", None)

    monkeypatch.setattr(
        "app.nis2.isms_docs.generator.ISMSDocumentGenerator.generate_document",
        _fake_generate_document,
    )

    gen_one = client.post(
        f"/nis2/isms/interview/{interview_id}/generate-one",
        json={"doc_type": "security_policy", "regenerate": True},
    )
    assert gen_one.status_code == 200
    doc_id = gen_one.get_json()["id"]

    assert client.get(f"/nis2/isms/interview/{interview_id}/documents").status_code == 200
    assert client.get(f"/nis2/isms/documents/{doc_id}").status_code == 200
    assert client.get(f"/nis2/isms/documents/{doc_id}/download").status_code == 200
    assert client.get(f"/nis2/isms/documents/{doc_id}/download.html").status_code == 200

    # Assets and risk register.
    asset_create = client.post(
        "/nis2/assets/new",
        data={
            "name": "ERP Core",
            "asset_type": "software",
            "criticality": "high",
            "patch_status": "outdated",
            "next_patch_due": "2025-01-01",
            "stores_personal_data": "on",
        },
        follow_redirects=False,
    )
    assert asset_create.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        asset = ITAsset.query.filter_by(user_id=user.id).first()
        assert asset is not None
        asset_id = asset.id

    assert client.post(f"/nis2/assets/{asset_id}/mark-patched", follow_redirects=False).status_code == 302
    assert client.post(
        f"/nis2/assets/{asset_id}/edit",
        data={"name": "ERP Core Updated", "asset_type": "software", "criticality": "high", "patch_status": "current"},
        follow_redirects=False,
    ).status_code == 302

    risk_create = client.post(
        "/nis2/risk-register/new",
        data={
            "title": "Credential stuffing",
            "category": "cyber_attack",
            "asset_id": str(asset_id),
            "likelihood": "4",
            "impact": "4",
            "treatment_type": "mitigate",
            "status": "open",
            "review_date": "2026-12-31",
        },
        follow_redirects=False,
    )
    assert risk_create.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        risk = Risk.query.filter_by(user_id=user.id).first()
        assert risk is not None
        risk_id = risk.id

    assert client.post(
        f"/nis2/risk-register/{risk_id}/edit",
        data={"title": "Credential stuffing", "likelihood": "3", "impact": "4", "status": "in_treatment"},
        follow_redirects=False,
    ).status_code == 302
    assert client.post(f"/nis2/risk-register/{risk_id}/close", follow_redirects=False).status_code == 302

    # Supply chain and DSGVO.
    supplier_add = client.post(
        "/nis2/supply-chain/add",
        data={
            "company_name": "Supplier Ops",
            "category": "it_service",
            "criticality": "high",
            "country": "DE",
            "vat_number": "DE123456789",
            "contact_email": "vendor@example.com",
            "services_provided": "SOC services",
            "avv_signed": "on",
        },
        follow_redirects=False,
    )
    assert supplier_add.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        supplier = Supplier.query.filter_by(user_id=user.id).first()
        assert supplier is not None
        supplier_id = supplier.id

    verify_resp = client.post(f"/nis2/supply-chain/{supplier_id}/verify")
    assert verify_resp.status_code == 200
    assert "risk_score" in verify_resp.get_json()

    assert client.post(
        f"/nis2/supply-chain/{supplier_id}/assess",
        data={"score": "42", "notes": "Quarterly review"},
        follow_redirects=False,
    ).status_code == 302

    dsgvo_create = client.post(
        "/nis2/dsgvo/art30/new",
        data={
            "name": "Customer support processing",
            "purpose": "Support tickets",
            "legal_basis": "contract",
            "data_categories": ["Name / Kontaktdaten", "E-Mail-Adresse"],
            "data_subjects": ["Kunden / Auftraggeber"],
            "processor_id": str(supplier_id),
            "next_review_date": "2026-12-31",
        },
        follow_redirects=False,
    )
    assert dsgvo_create.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        activity = ProcessingActivity.query.filter_by(user_id=user.id).first()
        assert activity is not None
        activity_id = activity.id

    assert client.get(f"/nis2/dsgvo/art30/{activity_id}/edit").status_code == 200
    assert client.get("/nis2/dsgvo/art30/export").status_code == 200

    # Monitoring with deterministic scanner patch.
    add_target = client.post(
        "/nis2/monitoring/targets/add",
        data={"domain": "example.com", "label": "Main", "scan_frequency": "monthly"},
        follow_redirects=False,
    )
    assert add_target.status_code == 302

    def _fake_scan(target, triggered_by="manual"):
        scan = MonitoringScan(
            target_id=target.id,
            scan_type="full",
            score=88.0,
            findings_count=1,
            critical_count=0,
            high_count=1,
            medium_count=0,
            low_count=0,
            triggered_by=triggered_by,
            scanned_at=datetime.now(UTC),
            results_json='{"status":"ok"}',
            diff_json='{}',
        )
        target.last_scan_at = scan.scanned_at
        target.next_scan_at = scan.scanned_at
        target.last_score = 88.0
        db.session.add(scan)
        db.session.commit()
        return scan

    monkeypatch.setattr("app.nis2.continuous_monitoring.scanner.run_scan_for_target", _fake_scan)

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        target = MonitoringTarget.query.filter_by(user_id=user.id).first()
        assert target is not None
        target_id = target.id

    scan_now = client.get(f"/nis2/monitoring/targets/{target_id}/scan-now", follow_redirects=False)
    assert scan_now.status_code == 302

    with flask_app.app_context():
        scan = MonitoringScan.query.join(MonitoringTarget).filter(MonitoringTarget.id == target_id).first()
        assert scan is not None
        scan_id = scan.id

    assert client.get(f"/nis2/monitoring/targets/{target_id}").status_code == 200
    assert client.get(f"/nis2/monitoring/scans/{scan_id}").status_code == 200
    assert client.get(f"/nis2/monitoring/scans/{scan_id}/report.html").status_code == 200
    assert client.get(f"/nis2/monitoring/api/trend/{target_id}").status_code == 200

    # Site audit with synchronous thread patch to verify pending->done transition.
    monkeypatch.setattr("app.nis2.site_audit.live_check.is_public_target", lambda _: True)

    def _fake_run_audit(job_id, target, log_fn):
        log_fn("INFO", "fake scan start")
        return {
            "findings": [
                {
                    "title": "Missing CSP",
                    "description": "No content-security-policy header",
                    "severity": "high",
                    "severity_rank": 2,
                    "cvss": "7.0",
                    "dsgvo_article": "Art. 32",
                    "recommendation": "Set CSP",
                    "tool": "headers",
                }
            ],
            "tasks": [
                {
                    "category": "Technisch",
                    "title": "Header hardening",
                    "description": "Set security headers",
                    "nis2_ref": "§30 Nr. 5",
                    "dsgvo_ref": "Art. 32",
                    "required": True,
                    "done": False,
                    "notes": "",
                }
            ],
            "live": {"target": target},
            "tools_used": ["python-check"],
        }

    monkeypatch.setattr("app.nis2.site_audit.audit_agent.run_audit", _fake_run_audit)

    class _ImmediateThread:
        def __init__(self, target, args=(), kwargs=None, daemon=None):
            self._target = target
            self._args = args
            self._kwargs = kwargs or {}

        def start(self):
            self._target(*self._args, **self._kwargs)

    monkeypatch.setattr("app.nis2.site_audit.routes.threading.Thread", _ImmediateThread)

    start_audit = client.post("/nis2/audit/start", data={"target": "https://example.com"}, follow_redirects=False)
    assert start_audit.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        job = NIS2AuditJob.query.filter_by(user_id=user.id).order_by(NIS2AuditJob.id.desc()).first()
        assert job is not None
        assert job.status == "done"
        job_id = job.id
        remediation = NIS2AuditTask.query.filter_by(job_id=job_id, category="Remediation").first()
        assert remediation is not None
        remediation_id = remediation.id

    assert client.get(f"/nis2/audit/{job_id}").status_code == 200
    assert client.get(f"/nis2/audit/{job_id}/logs").status_code == 200
    assert client.get(f"/nis2/audit/{job_id}/report").status_code == 200
    assert client.get(f"/nis2/audit/{job_id}/download").status_code == 200

    update_task = client.post(
        f"/nis2/audit/{job_id}/tasks/{remediation_id}/update",
        data={"done": "1", "notes": "fixed", "retest_job_id": str(job_id)},
        follow_redirects=False,
    )
    assert update_task.status_code == 302

    # Training flow without SMTP dependency.
    training_create = client.post(
        "/nis2/training/create",
        data={
            "topic": "general",
            "title": "Ops Training",
            "content_md": "# Content",
            "audience": "Alice <alice@example.com>",
        },
        follow_redirects=False,
    )
    assert training_create.status_code == 302

    with flask_app.app_context():
        user = User.query.filter_by(email="ops@example.com").first()
        training = SecurityTraining.query.filter_by(user_id=user.id).order_by(SecurityTraining.id.desc()).first()
        assert training is not None
        training_id = training.id

    assert client.post(
        f"/nis2/training/{training_id}/gf-acknowledge",
        data={"gf_name": "Ops GF"},
        follow_redirects=False,
    ).status_code == 302
    assert client.post(f"/nis2/training/{training_id}/send", follow_redirects=False).status_code == 302

    with flask_app.app_context():
        ack = TrainingAcknowledgment.query.filter_by(training_id=training_id).first()
        assert ack is not None
        token = ack.token

    assert client.get(f"/nis2/training/ack/{token}").status_code == 200
    ack_post = client.post(
        f"/nis2/training/ack/{token}",
        data={"confirmed_name": "Alice", "confirm_read": "on"},
    )
    assert ack_post.status_code == 200
    assert client.get(f"/nis2/training/ack/{token}/certificate").status_code == 200
    assert client.get(f"/nis2/training/{training_id}/report").status_code == 200

    # Incidents: create/update/timeline/draft generation (without real BSI submission).
    incident_create = client.post(
        "/nis2/incidents/create",
        data={
            "title": "Unauthorized access",
            "category": "cyberangriff",
            "severity": "high",
            "description": "Suspicious login",
            "affected_systems": "VPN",
            "affected_data": "Credentials",
        },
        follow_redirects=False,
    )
    assert incident_create.status_code == 302
    incident_location = incident_create.headers["Location"]
    incident_id = int(incident_location.rstrip("/").split("/")[-1])

    assert client.post(
        f"/nis2/incidents/{incident_id}/update",
        data={"status": "contained", "mitigation_steps": "Account reset"},
        follow_redirects=False,
    ).status_code == 302

    assert client.post(
        f"/nis2/incidents/{incident_id}/timeline/add",
        data={"note": "Forensics started"},
        follow_redirects=False,
    ).status_code == 302

    monkeypatch.setattr(
        "app.nis2.incident_response.routes.generate_bsi_draft",
        lambda stage, data: (f"Draft for {stage}", None),
    )

    draft_resp = client.post(
        f"/nis2/incidents/{incident_id}/generate-draft",
        json={"stage": "fruehwarnung", "company_name": "Ops GmbH", "contact_name": "Ops GF", "contact_email": "ops@example.com"},
    )
    assert draft_resp.status_code == 200
    draft_id = draft_resp.get_json()["draft_id"]

    assert client.get(f"/nis2/incidents/{incident_id}/draft/{draft_id}").status_code == 200
    assert client.post(
        f"/nis2/incidents/{incident_id}/draft/{draft_id}/save",
        data={"content": "Edited draft"},
        follow_redirects=False,
    ).status_code == 302

    # Unified deadlines + full compliance report render.
    assert client.get("/nis2/fristen/").status_code == 200
    assert client.get("/nis2/compliance-report/").status_code == 200
