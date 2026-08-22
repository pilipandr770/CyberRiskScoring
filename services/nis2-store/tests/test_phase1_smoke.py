import sys
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pyotp

from app.extensions import db
from app.models import User
from app.nis2.models import MonitoringTarget, BSIRegistration


def _create_user(email: str, password: str, plan: str = "basic") -> User:
    user = User(
        email=email,
        subscription_plan=plan,
        trial_ends_at=datetime.now(UTC) + timedelta(days=14),
        is_active=True,
        is_email_confirmed=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, email: str, password: str):
    return client.post(
        "/auth/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def test_auth_login_requires_mfa_and_verifies_totp(flask_app, client):
    with flask_app.app_context():
        user = _create_user("mfa@example.com", "Secret123!", plan="basic")
        user.generate_totp_secret()
        user.totp_enabled = True
        db.session.commit()
        code = pyotp.TOTP(user.totp_secret).now()

    login_resp = _login(client, "mfa@example.com", "Secret123!")
    assert login_resp.status_code == 302
    assert "/auth/mfa/verify" in login_resp.headers["Location"]

    verify_resp = client.post(
        "/auth/mfa/verify",
        data={"code": code},
        follow_redirects=False,
    )
    assert verify_resp.status_code == 302
    assert "/nis2/" in verify_resp.headers["Location"]

    with client.session_transaction() as sess:
        assert sess.get("_user_id") is not None


def test_dashboard_compliance_score_api_returns_shape(flask_app, client):
    with flask_app.app_context():
        _create_user("dash@example.com", "Secret123!", plan="basic")

    login_resp = _login(client, "dash@example.com", "Secret123!")
    assert login_resp.status_code == 302

    resp = client.get("/nis2/api/compliance-score")
    assert resp.status_code == 200

    payload = resp.get_json()
    assert "total_score" in payload
    assert "measures" in payload
    assert len(payload["measures"]) == 10


def test_monitoring_scan_now_uses_manual_trigger(flask_app, client, monkeypatch):
    with flask_app.app_context():
        user = _create_user("pro@example.com", "Secret123!", plan="professional")
        target = MonitoringTarget(
            user_id=user.id,
            domain="example.com",
            label="Main",
            scan_frequency="monthly",
            next_scan_at=datetime.now(UTC),
        )
        db.session.add(target)
        db.session.commit()
        target_id = target.id

    login_resp = _login(client, "pro@example.com", "Secret123!")
    assert login_resp.status_code == 302

    seen = {"triggered_by": None, "target_id": None}

    def _fake_scan(target, triggered_by="scheduler"):
        seen["triggered_by"] = triggered_by
        seen["target_id"] = target.id
        return SimpleNamespace(score=88.0)

    monkeypatch.setattr("app.nis2.continuous_monitoring.scanner.run_scan_for_target", _fake_scan)

    resp = client.get(f"/nis2/monitoring/targets/{target_id}/scan-now", follow_redirects=False)
    assert resp.status_code == 302
    assert seen["triggered_by"] == "manual"
    assert seen["target_id"] == target_id


def test_stripe_webhook_updates_subscription(flask_app, client, monkeypatch):
    with flask_app.app_context():
        user = _create_user("bill@example.com", "Secret123!", plan="trial")
        user.stripe_customer_id = "cus_123"
        db.session.commit()

    flask_app.config["STRIPE_WEBHOOK_SECRET"] = "whsec_test"
    flask_app.config["STRIPE_PRICE_PROFESSIONAL"] = "price_pro"

    event = {
        "type": "customer.subscription.updated",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_123",
                "items": {"data": [{"price": {"id": "price_pro"}}]},
            }
        },
    }

    class _Webhook:
        @staticmethod
        def construct_event(payload, sig_header, secret):
            return event

    monkeypatch.setitem(sys.modules, "stripe", SimpleNamespace(Webhook=_Webhook))

    resp = client.post(
        "/payments/webhook",
        data=b"{}",
        headers={"Stripe-Signature": "sig_test"},
    )
    assert resp.status_code == 200

    with flask_app.app_context():
        updated = User.query.filter_by(email="bill@example.com").first()
        assert updated.subscription_plan == "professional"
        assert updated.stripe_subscription_id == "sub_123"


def test_bsi_export_renders_contacts_mapping(flask_app, client):
    with flask_app.app_context():
        user = _create_user("bsi@example.com", "Secret123!", plan="professional")
        reg = BSIRegistration(
            user_id=user.id,
            company_name="Acme GmbH",
            legal_form="GmbH",
            entity_type="wichtig",
            is_complete=True,
            contacts_json='{"gf": {"name": "Max", "email": "max@example.com", "phone": "+49"}}',
            technical_json='{}',
        )
        db.session.add(reg)
        db.session.commit()
        reg_id = reg.id

    login_resp = _login(client, "bsi@example.com", "Secret123!")
    assert login_resp.status_code == 302

    resp = client.get(f"/nis2/bsi-registration/{reg_id}/export")
    assert resp.status_code == 200
    assert "Ansprechpartner" in resp.get_data(as_text=True)
