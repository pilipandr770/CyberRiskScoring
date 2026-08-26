"""
Provisioning receiver — the inbound side of the M2 -> M3 handoff.

Called by risk-scanner (Module 2) when an underwriter accepts a decision
(see services/risk-scanner/app/m3_provisioning.py on the other side).
This is now the *only* way a company account gets created on this
platform — there's no public self-service signup anymore (access is
insurer-gated, see auth/routes.py's disabled /register route).

Auth: static API key (X-API-Key), must match M3_PROVISIONING_API_KEY —
mirrors risk-scanner's own inbound machine-API auth pattern.
"""

import json
import logging
import secrets
from datetime import UTC, datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from flask_mail import Message

from app.extensions import csrf, db, mail
from app.models import User
from .models import MonitoringScan, MonitoringTarget

logger = logging.getLogger(__name__)
provisioning_bp = Blueprint('provisioning', __name__)

_SEVERITY_PENALTY = {'critical': 20, 'high': 10, 'medium': 5, 'low': 2, 'info': 0}


def _check_api_key() -> bool:
    expected = current_app.config.get('M3_PROVISIONING_API_KEY')
    return bool(expected) and request.headers.get('X-API-Key') == expected


def _build_baseline_scan_data(findings: list[dict]) -> tuple[float, dict, dict]:
    """Groups M1's findings by tool into the same {status, issues:[...]}
    shape live_check.run_basic_checks() already produces for continuous-
    monitoring scans, so this baseline renders on the dashboard exactly
    like any later scan — not a special-cased second format."""
    checks: dict[str, dict] = {}
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    score = 100.0

    for f in findings:
        sev = f.get('severity', 'info')
        if sev in counts:
            counts[sev] += 1
        score -= _SEVERITY_PENALTY.get(sev, 0)

        group = checks.setdefault(f.get('tool', 'scan'), {'status': 'PASSED', 'issues': []})
        group['issues'].append({
            'severity': sev,
            'title': f.get('title'),
            'description': f.get('description'),
            'recommendation': f.get('recommendation'),
        })
        if sev in ('critical', 'high'):
            group['status'] = 'FAILED'
        elif sev == 'medium' and group['status'] == 'PASSED':
            group['status'] = 'WARNING'

    return max(0.0, min(100.0, round(score, 1))), checks, counts


@provisioning_bp.route('/provisioning/webhook', methods=['POST'])
@csrf.exempt
def provisioning_webhook():
    if not _check_api_key():
        return jsonify({'error': 'unauthorized'}), 401

    payload = request.get_json(silent=True) or {}
    company_name = (payload.get('company_name') or '').strip()
    domain = (payload.get('domain') or '').strip()
    contact_email = (payload.get('contact_email') or '').strip().lower()
    scan_id = payload.get('scan_id')
    # Explicit resend request (agent clicked "send access email again" in
    # risk-scanner) — without this, an account that already existed (e.g.
    # from an earlier test, or the client's original welcome email having
    # expired unused) silently got no email at all on every later call,
    # with no way to trigger one again. See the `if created:` gate below.
    force_resend = bool(payload.get('force_resend'))

    if not company_name or not domain:
        return jsonify({'error': 'company_name and domain are required'}), 400

    if not contact_email:
        # No contact email collected yet on the risk-scanner intake side —
        # can't create a login without one. Recorded, not silently dropped.
        logger.warning('Provisioning call for %s (%s) has no contact_email — '
                       'cannot create a login. scan_id=%s', company_name, domain, scan_id)
        return jsonify({'error': 'contact_email missing — cannot create account', 'scan_id': scan_id}), 422

    user = User.query.filter_by(email=contact_email).first()
    created = False
    if not user:
        user = User(
            email=contact_email,
            company_name=company_name,
            subscription_plan='active',  # no tiers — provisioned accounts get full access
            registration_ip='provisioned-by-m2',
        )
        user.set_password(secrets.token_urlsafe(24))  # unusable random password — set via reset link
        db.session.add(user)
        created = True

    db.session.flush()  # need user.id for the FK below

    target = MonitoringTarget.query.filter_by(user_id=user.id, domain=domain).first()
    if not target:
        target = MonitoringTarget(
            user_id=user.id,
            domain=domain,
            label='Hauptwebsite (aus Modul 1 übernommen)',
            scan_frequency='monthly',
            alert_email=contact_email,
            next_scan_at=datetime.now(UTC) + timedelta(days=30),
        )
        db.session.add(target)
        db.session.flush()  # need target.id for the baseline scan below

        baseline_findings = payload.get('baseline_findings') or []
        if baseline_findings:
            score, checks, counts = _build_baseline_scan_data(baseline_findings)
            baseline_scan = MonitoringScan(
                target_id=target.id,
                scan_type='full',
                score=score,
                results_json=json.dumps(
                    {'overall_score': score, 'checks': checks, 'source': 'module1_baseline'},
                    ensure_ascii=False,
                ),
                findings_count=len(baseline_findings),
                critical_count=counts['critical'],
                high_count=counts['high'],
                medium_count=counts['medium'],
                low_count=counts['low'],
                triggered_by='m2_provisioning',
                scanned_at=datetime.now(UTC),
            )
            db.session.add(baseline_scan)
            target.last_score = score
            target.last_scan_at = datetime.now(UTC)

    db.session.commit()

    email_sent = False
    email_error = None
    if created or force_resend:
        token = user.generate_reset_token()
        db.session.commit()
        try:
            _send_welcome_email(user, token)
            email_sent = True
        except Exception as exc:
            logger.warning('Could not send welcome email to %s: %s', contact_email, exc)
            email_error = str(exc)

    return jsonify({
        'status': 'ok', 'created': created, 'user_id': user.id,
        'email_sent': email_sent, 'email_error': email_error,
    }), 200


def _send_welcome_email(user: User, token: str):
    from flask import current_app, url_for
    # This handler runs inside an inbound webhook call from risk-scanner
    # (http://nis2-store:5000/...), not a real browser request — so
    # url_for(_external=True) built the link from THAT request's Host
    # header ("nis2-store:5000", the internal docker hostname), producing
    # an email link no client outside the docker network could ever open.
    # Building it from the app's own configured public base URL instead.
    base_url = (current_app.config.get('BASE_URL') or '').rstrip('/')
    setup_url = base_url + url_for('auth.reset_password', token=token)
    msg = Message(
        subject='Ihr Zugang zum NIS2-Compliance-Portal',
        recipients=[user.email],
        html=(
            f'<p>Ihre Cyber-Versicherung hat Ihnen einen Zugang zum NIS2-Compliance-Portal '
            f'eingerichtet.</p><p>Bitte legen Sie hier Ihr Passwort fest: '
            f'<a href="{setup_url}">{setup_url}</a></p>'
        ),
    )
    mail.send(msg)
