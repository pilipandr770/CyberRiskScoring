from datetime import UTC, datetime, timedelta

from app.extensions import db
from app.models import User
from app.nis2.models import (
    BSIRegistration,
    ISMSDocument,
    ISMSInterview,
    ITAsset,
    MonitoringScan,
    MonitoringTarget,
    SecurityTraining,
    Supplier,
    TrainingAcknowledgment,
)


def test_full_user_cycle_to_100_percent_compliance(flask_app, client):
    email = "cycle@example.com"
    password = "Secret123!"

    # 1) Register new user through real auth flow.
    register_resp = client.post(
        "/auth/register",
        data={
            "email": email,
            "password": password,
            "password2": password,
            "company_name": "Cycle GmbH",
            "first_name": "Max",
            "last_name": "Tester",
        },
        follow_redirects=False,
    )
    assert register_resp.status_code == 302
    assert "/nis2/" in register_resp.headers["Location"]

    # 2) Run BSI wizard end-to-end using routes.
    start_resp = client.post("/nis2/bsi-registration/wizard/start", follow_redirects=False)
    assert start_resp.status_code == 302
    assert "/nis2/bsi-registration/wizard/" in start_resp.headers["Location"]

    with flask_app.app_context():
        user = User.query.filter_by(email=email).first()
        assert user is not None
        reg = BSIRegistration.query.filter_by(user_id=user.id, is_complete=False).first()
        assert reg is not None
        reg_id = reg.id

    step1 = client.post(
        f"/nis2/bsi-registration/wizard/{reg_id}/step/1",
        data={
            "company_name": "Cycle GmbH",
            "legal_form": "GmbH",
            "employee_count": "250",
            "annual_revenue_eur": "12000000",
        },
        follow_redirects=False,
    )
    assert step1.status_code == 302

    step2 = client.post(
        f"/nis2/bsi-registration/wizard/{reg_id}/step/2",
        data={"sector": "digital_cloud", "subsector": "Cloud"},
        follow_redirects=False,
    )
    assert step2.status_code == 302

    step3 = client.post(
        f"/nis2/bsi-registration/wizard/{reg_id}/step/3",
        data={
            "gf_name": "Max GF",
            "gf_email": "gf@example.com",
            "ciso_name": "Alice CISO",
            "ciso_email": "ciso@example.com",
        },
        follow_redirects=False,
    )
    assert step3.status_code == 302

    step4 = client.post(
        f"/nis2/bsi-registration/wizard/{reg_id}/step/4",
        data={
            "ip_ranges": "203.0.113.0/24",
            "domains": "example.com",
            "cloud_providers": "AWS,Azure",
            "it_services": "SOC, SIEM",
            "employee_count_it": "12",
        },
        follow_redirects=False,
    )
    assert step4.status_code == 302

    step5 = client.post(
        f"/nis2/bsi-registration/wizard/{reg_id}/step/5",
        data={"confirm": "1"},
        follow_redirects=False,
    )
    assert step5.status_code == 302

    export_resp = client.get(f"/nis2/bsi-registration/{reg_id}/export")
    assert export_resp.status_code == 200

    # 3) Fill data required for 100% compliance score.
    with flask_app.app_context():
        user = User.query.filter_by(email=email).first()

        interview = ISMSInterview(user_id=user.id, company_name="Cycle GmbH", is_complete=True, current_phase=4)
        db.session.add(interview)
        db.session.flush()

        for doc_type in [
            "security_policy",
            "risk_analysis",
            "incident_response_plan",
            "bcm_plan",
            "supply_chain_policy",
            "crypto_concept",
            "access_control",
            "mfa_communication",
        ]:
            db.session.add(
                ISMSDocument(
                    user_id=user.id,
                    interview_id=interview.id,
                    doc_type=doc_type,
                    title=doc_type,
                    content_md="# Generated",
                    content="# Generated",
                    is_generated=True,
                )
            )

        target = MonitoringTarget(
            user_id=user.id,
            domain="example.com",
            label="Main",
            is_active=True,
            scan_frequency="monthly",
            last_score=90.0,
            previous_score=85.0,
            last_scan_at=datetime.now(UTC),
            next_scan_at=datetime.now(UTC) + timedelta(days=30),
        )
        db.session.add(target)
        db.session.flush()

        for i in range(4):
            db.session.add(
                MonitoringScan(
                    target_id=target.id,
                    scan_type="full",
                    score=90.0,
                    findings_count=0,
                    critical_count=0,
                    high_count=0,
                    medium_count=0,
                    low_count=0,
                    triggered_by="manual",
                    scanned_at=datetime(datetime.now(UTC).year, 1, 5 + i),
                    results_json="{}",
                    diff_json="{}",
                )
            )

        db.session.add(
            ITAsset(
                user_id=user.id,
                name="ERP",
                asset_type="software",
                criticality="high",
                is_active=True,
            )
        )

        db.session.add(
            Supplier(
                user_id=user.id,
                company_name="Supplier One",
                is_active=True,
                last_verification_at=datetime.now(UTC),
            )
        )

        training1 = SecurityTraining(
            user_id=user.id,
            title="Phishing Basics",
            topic="phishing",
            content_md="content",
            status="sent",
            gf_acknowledged=True,
            gf_acknowledged_at=datetime.now(UTC),
        )
        training2 = SecurityTraining(
            user_id=user.id,
            title="MFA Basics",
            topic="passwords",
            content_md="content",
            status="sent",
            gf_acknowledged=False,
        )
        db.session.add(training1)
        db.session.add(training2)
        db.session.flush()

        db.session.add(
            TrainingAcknowledgment(
                training_id=training1.id,
                recipient_name="Employee One",
                recipient_email="employee@example.com",
                token="ack-token-1",
                acknowledged=True,
                acknowledged_at=datetime.now(UTC),
            )
        )

        db.session.commit()

    # 4) Check resulting score is fully complete.
    score_resp = client.get("/nis2/api/compliance-score")
    assert score_resp.status_code == 200
    score = score_resp.get_json()
    assert score["total_score"] == 100.0
    assert score["complete_count"] == 10
    assert score["open_count"] == 0

    # 5) Smoke-check critical module pages for this user journey.
    for path in [
        "/nis2/",
        "/nis2/bsi-registration/",
        f"/nis2/bsi-registration/{reg_id}/export",
        "/nis2/isms/",
        "/nis2/monitoring/",
        "/nis2/incidents/",
        "/nis2/supply-chain/",
        "/nis2/training/",
        "/nis2/risk-register/",
        "/nis2/dsgvo/art30/",
    ]:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
