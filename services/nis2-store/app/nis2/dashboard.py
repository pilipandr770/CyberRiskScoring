"""
NIS2 Compliance Score Dashboard.

Calculates §30 BSIG compliance status across all 10 mandatory measures
and provides the main NIS2 hub page.
"""

from flask import render_template, jsonify
from flask_login import login_required, current_user


def register_dashboard_routes(bp):

    @bp.route('/')
    @login_required
    def dashboard():
        score_data = _calculate_compliance_score(current_user.id)
        return render_template('nis2/dashboard.html', score_data=score_data)

    @bp.route('/api/compliance-score')
    @login_required
    def compliance_score_api():
        data = _calculate_compliance_score(current_user.id)
        reg = data.get('bsi_registration')
        if reg is not None:
            data['bsi_registration'] = {
                'id': reg.id,
                'company_name': reg.company_name,
                'entity_type': reg.entity_type,
                'is_complete': reg.is_complete,
                'wizard_step': reg.wizard_step,
                'exported_at': reg.exported_at.isoformat() if reg.exported_at else None,
            }
        return jsonify(data)


def _calculate_compliance_score(user_id: int) -> dict:
    """
    Calculates NIS2 compliance coverage for §30 Abs. 2 BSIG (10 measures).
    Returns a dict with per-measure status and overall percentage.
    """
    from .models import (
        ISMSDocument, MonitoringScan, MonitoringTarget,
        Incident, Supplier, BSIRegistration,
    )
    from datetime import UTC, datetime

    measures = {}

    # ── Nr. 1: Risikoanalyse & IT-Sicherheit ─────────────────────────────
    isms_types = {d.doc_type for d in
                  ISMSDocument.query.filter_by(user_id=user_id, is_generated=True).all()}
    nr1_docs = {'risk_analysis', 'security_policy'} & isms_types
    measures['nr1'] = {
        'label': 'Risikoanalyse & IT-Sicherheitsleitlinie',
        'paragraph': '§30 Nr. 1',
        'score': min(100, len(nr1_docs) * 50),
        'status': 'complete' if len(nr1_docs) >= 2 else ('partial' if nr1_docs else 'open'),
        'action_url': '/nis2/isms/',
        'action_label': 'Dokument erstellen',
        'icon': 'bi-file-earmark-text',
    }

    # ── Nr. 2: Incident Response ─────────────────────────────────────────
    has_irp = 'incident_response_plan' in isms_types
    has_bcm = 'bcm_plan' in isms_types
    nr2_score = (50 if has_irp else 0) + (50 if has_bcm else 0)
    measures['nr2'] = {
        'label': 'Sicherheitsvorfälle & Incident Response',
        'paragraph': '§30 Nr. 2',
        'score': nr2_score,
        'status': 'complete' if nr2_score == 100 else ('partial' if nr2_score > 0 else 'open'),
        'action_url': '/nis2/incidents/',
        'action_label': 'Incident melden',
        'icon': 'bi-exclamation-triangle',
    }

    # ── Nr. 3: BCM / Backup / Krisenmanagement ───────────────────────────
    measures['nr3'] = {
        'label': 'Betriebsaufrechterhaltung (BCM/BCP)',
        'paragraph': '§30 Nr. 3',
        'score': 100 if has_bcm else 0,
        'status': 'complete' if has_bcm else 'open',
        'action_url': '/nis2/isms/',
        'action_label': 'BCP erstellen',
        'icon': 'bi-shield-check',
    }

    # ── Nr. 4: Lieferkettensicherheit ────────────────────────────────────
    supplier_count = Supplier.query.filter_by(user_id=user_id, is_active=True).count()
    from sqlalchemy import or_
    assessed_count = Supplier.query.filter(
        Supplier.user_id == user_id,
        Supplier.is_active == True,
        or_(
            Supplier.last_verification_at.isnot(None),
            Supplier.last_assessment_at.isnot(None),
        ),
    ).count()
    sc_score = 0
    if supplier_count > 0:
        sc_score = min(100, int(assessed_count / supplier_count * 100))
    elif 'supply_chain_policy' in isms_types:
        sc_score = 30
    measures['nr4'] = {
        'label': 'Sicherheit der Lieferkette',
        'paragraph': '§30 Nr. 4',
        'score': sc_score,
        'status': 'complete' if sc_score >= 80 else ('partial' if sc_score > 0 else 'open'),
        'action_url': '/nis2/supply-chain/',
        'action_label': 'Lieferanten verwalten',
        'icon': 'bi-diagram-3',
    }

    # ── Nr. 5: Schwachstellenmanagement ──────────────────────────────────
    from .models import ITAsset
    scan_count = MonitoringScan.query.join(MonitoringTarget).filter(
        MonitoringTarget.user_id == user_id
    ).count()
    asset_count = ITAsset.query.filter_by(user_id=user_id, is_active=True).count()
    nr5_score = min(100, (50 if scan_count > 0 else 0) + (50 if asset_count > 0 else 0))
    measures['nr5'] = {
        'label': 'Schwachstellenmanagement & Sicherheitsprüfung',
        'paragraph': '§30 Nr. 5',
        'score': nr5_score,
        'status': 'complete' if nr5_score == 100 else ('partial' if nr5_score > 0 else 'open'),
        'detail': f'{asset_count} Asset(s) im Inventar, {scan_count} Scan(s)',
        'action_url': '/nis2/assets/' if asset_count == 0 else '/nis2/monitoring/',
        'action_label': 'Asset-Inventar' if asset_count == 0 else 'Scan starten',
        'icon': 'bi-radar',
    }

    # ── Nr. 6: Wirksamkeitsbewertung ─────────────────────────────────────
    recent_scans = MonitoringScan.query.join(MonitoringTarget).filter(
        MonitoringTarget.user_id == user_id,
        MonitoringScan.scanned_at >= datetime(datetime.now(UTC).year, 1, 1),
    ).count()
    measures['nr6'] = {
        'label': 'Bewertung der Wirksamkeit der Maßnahmen',
        'paragraph': '§30 Nr. 6',
        'score': min(100, recent_scans * 25),
        'status': 'complete' if recent_scans >= 4 else ('partial' if recent_scans > 0 else 'open'),
        'action_url': '/nis2/monitoring/',
        'action_label': 'Monitoring einrichten',
        'icon': 'bi-graph-up',
    }

    # ── Nr. 7: Schulungen & Sensibilisierung (inkl. §38 GF-Bestätigung) ────
    from .models import SecurityTraining, TrainingAcknowledgment
    from app.extensions import db
    total_trainings = SecurityTraining.query.filter_by(user_id=user_id).count()
    gf_ack_count = SecurityTraining.query.filter_by(
        user_id=user_id, gf_acknowledged=True
    ).count()
    # Count distinct staff who confirmed at least one training
    confirmed_acks = (
        db.session.query(TrainingAcknowledgment.recipient_email)
        .join(SecurityTraining, TrainingAcknowledgment.training_id == SecurityTraining.id)
        .filter(SecurityTraining.user_id == user_id,
                TrainingAcknowledgment.acknowledged == True)
        .distinct()
        .count()
    )
    # Score: 25 per sent training (max 50) + 25 for §38 GF-Bestätigung + 25 if staff acks exist
    nr7_score = (min(50, total_trainings * 25)
                 + (25 if gf_ack_count > 0 else 0)
                 + (25 if confirmed_acks > 0 else 0))
    nr7_status = ('complete' if nr7_score >= 100
                  else ('partial' if nr7_score > 0 else 'open'))
    par38_label = f'§38 GF-Best.: {gf_ack_count} Schulung(en)' if gf_ack_count > 0 else '§38 GF-Bestätigung ausstehend'
    measures['nr7'] = {
        'label': 'Schulungen & Cyber-Hygiene-Sensibilisierung',
        'paragraph': '§30 Nr. 7 / §38',
        'score': nr7_score,
        'status': nr7_status,
        'detail': f'{total_trainings} Schulung(en), {confirmed_acks} Mitarbeiter bestätigt — {par38_label}',
        'action_url': '/nis2/training/',
        'action_label': 'Schulung erstellen',
        'icon': 'bi-mortarboard',
    }

    # ── Nr. 8: Kryptographie ─────────────────────────────────────────────
    has_crypto = 'crypto_concept' in isms_types
    # Check if any monitoring target has TLS scan
    tls_scanned = MonitoringTarget.query.filter(
        MonitoringTarget.user_id == user_id,
        MonitoringTarget.last_score.isnot(None),
    ).count() > 0
    crypto_score = (50 if has_crypto else 0) + (50 if tls_scanned else 0)
    measures['nr8'] = {
        'label': 'Kryptographie & Verschlüsselung',
        'paragraph': '§30 Nr. 8',
        'score': crypto_score,
        'status': 'complete' if crypto_score == 100 else ('partial' if crypto_score > 0 else 'open'),
        'action_url': '/nis2/isms/',
        'action_label': 'Krypto-Konzept erstellen',
        'icon': 'bi-lock',
    }

    # ── Nr. 9: Personelle Sicherheit / IAM / Asset Management ────────────
    has_iam = 'access_control' in isms_types
    nr9_score = (50 if has_iam else 0) + (50 if asset_count > 0 else 0)
    measures['nr9'] = {
        'label': 'Zugriffskontrolle & Asset-Management',
        'paragraph': '§30 Nr. 9',
        'score': nr9_score,
        'status': 'complete' if nr9_score == 100 else ('partial' if nr9_score > 0 else 'open'),
        'detail': f'IAM-Konzept: {"✓" if has_iam else "fehlt"} · Assets: {asset_count}',
        'action_url': '/nis2/assets/' if asset_count == 0 else '/nis2/isms/',
        'action_label': 'Asset-Inventar' if asset_count == 0 else 'IAM-Konzept erstellen',
        'icon': 'bi-person-lock',
    }

    # ── Nr. 10: MFA & sichere Kommunikation ──────────────────────────────
    has_mfa = 'mfa_communication' in isms_types
    measures['nr10'] = {
        'label': 'MFA & gesicherte Kommunikation',
        'paragraph': '§30 Nr. 10',
        'score': 100 if has_mfa else 0,
        'status': 'complete' if has_mfa else 'open',
        'action_url': '/nis2/isms/',
        'action_label': 'MFA-Policy erstellen',
        'icon': 'bi-phone-vibrate',
    }

    # ── Overall score ─────────────────────────────────────────────────────
    total = sum(m['score'] for m in measures.values()) / len(measures)

    # ── BSI Registration status ───────────────────────────────────────────
    bsi_reg = BSIRegistration.query.filter_by(
        user_id=user_id, is_complete=True
    ).first()

    # ── Quick stats ───────────────────────────────────────────────────────
    open_incidents = Incident.query.filter_by(user_id=user_id, status='open').count()
    active_suppliers = Supplier.query.filter_by(user_id=user_id, is_active=True).count()
    monitoring_targets = MonitoringTarget.query.filter_by(user_id=user_id, is_active=True).count()
    docs_generated = ISMSDocument.query.filter_by(user_id=user_id, is_generated=True).count()

    # Next recommended actions
    next_actions = _get_next_actions(measures, bsi_reg, open_incidents)

    return {
        'measures': measures,
        'total_score': round(total, 1),
        'complete_count': sum(1 for m in measures.values() if m['status'] == 'complete'),
        'partial_count': sum(1 for m in measures.values() if m['status'] == 'partial'),
        'open_count': sum(1 for m in measures.values() if m['status'] == 'open'),
        'bsi_registered': bsi_reg is not None,
        'bsi_registration': bsi_reg,
        'open_incidents': open_incidents,
        'active_suppliers': active_suppliers,
        'monitoring_targets': monitoring_targets,
        'docs_generated': docs_generated,
        'next_actions': next_actions,
    }


def _get_next_actions(measures, bsi_reg, open_incidents):
    actions = []

    if not bsi_reg:
        actions.append({
            'priority': 'urgent',
            'text': 'BSI-Registrierung noch nicht abgeschlossen (§33 BSIG)',
            'url': '/nis2/bsi-registration/',
            'icon': 'bi-building',
        })

    if open_incidents > 0:
        actions.append({
            'priority': 'urgent',
            'text': f'{open_incidents} offene(r) Sicherheitsvorfall/-vorfälle — BSI-Meldung prüfen',
            'url': '/nis2/incidents/',
            'icon': 'bi-exclamation-octagon',
        })

    for key, m in measures.items():
        if m['status'] == 'open':
            actions.append({
                'priority': 'high',
                'text': f"{m['paragraph']}: {m['label']} — noch nicht umgesetzt",
                'url': m['action_url'],
                'icon': m['icon'],
            })

    for key, m in measures.items():
        if m['status'] == 'partial':
            actions.append({
                'priority': 'medium',
                'text': f"{m['paragraph']}: {m['label']} — teilweise umgesetzt",
                'url': m['action_url'],
                'icon': m['icon'],
            })

    return actions[:6]  # Show max 6
