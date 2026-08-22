"""
§39 BSIG — Compliance Package Export

Generates a comprehensive HTML compliance report covering all §30 measures,
§32 incident reporting, §33 BSI registration, and §38 GF training obligations.
Serves as the evidence package for BSI audits and internal governance reviews.
"""

from datetime import UTC, datetime, date

from flask import render_template, make_response, request
from flask_login import current_user, login_required

from app.extensions import db
from ..models import (
    BSIRegistration,
    ISMSDocument, ISMSInterview, ISMS_DOC_TYPES,
    Incident,
    SecurityTraining, TrainingAcknowledgment,
    MonitoringTarget, MonitoringScan,
    Supplier,
    NIS2AuditJob,
    ITAsset,
)
from ..dashboard import _calculate_compliance_score


def register_compliance_report_routes(bp):

    @bp.route('/compliance-report/')
    @login_required
    def compliance_report():
        data = _collect_report_data(current_user.id)
        as_pdf = request.args.get('pdf') == '1'
        if as_pdf:
            html = render_template('nis2/compliance_report/index.html',
                                   **data, print_mode=True)
            resp = make_response(html)
            resp.headers['Content-Type'] = 'text/html; charset=utf-8'
            resp.headers['Content-Disposition'] = (
                f'attachment; filename="NIS2-Compliance-Report-'
                f'{datetime.now(UTC).strftime("%Y%m%d")}.html"'
            )
            return resp
        return render_template('nis2/compliance_report/index.html',
                               **data, print_mode=False)

    @bp.route('/compliance-report/download')
    @login_required
    def compliance_report_download():
        data = _collect_report_data(current_user.id)
        html = render_template('nis2/compliance_report/index.html',
                               **data, print_mode=True)
        resp = make_response(html)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['Content-Disposition'] = (
            f'attachment; filename="NIS2-Compliance-Report-'
            f'{datetime.now(UTC).strftime("%Y%m%d")}.html"'
        )
        return resp


# ─────────────────────────────────────────────────────────────────
# Data collection
# ─────────────────────────────────────────────────────────────────

def _collect_report_data(user_id: int) -> dict:
    score_data = _calculate_compliance_score(user_id)
    now = datetime.now(UTC)
    today = date.today()

    # ── BSI Registration (§33) ────────────────────────────────────
    bsi_reg = BSIRegistration.query.filter_by(user_id=user_id).order_by(
        BSIRegistration.updated_at.desc()
    ).first()

    # ── ISMS Documents ────────────────────────────────────────────
    existing_docs = {
        d.doc_type: d
        for d in ISMSDocument.query.filter_by(user_id=user_id).all()
    }
    isms_rows = []
    for doc_type, title, paragraph, bsi_std in ISMS_DOC_TYPES:
        doc = existing_docs.get(doc_type)
        isms_rows.append({
            'doc_type': doc_type,
            'title': title,
            'paragraph': paragraph,
            'bsi_std': bsi_std,
            'exists': doc is not None and doc.is_generated,
            'doc': doc,
        })

    isms_complete = sum(1 for r in isms_rows if r['exists'])
    isms_total = len(isms_rows)

    # ── Incidents (§32) ───────────────────────────────────────────
    incidents = Incident.query.filter_by(user_id=user_id).order_by(
        Incident.detected_at.desc()
    ).all()

    incidents_summary = {
        'total': len(incidents),
        'open': sum(1 for i in incidents if i.status == 'open'),
        'closed': sum(1 for i in incidents if i.status == 'closed'),
        'fruehwarnung_overdue': sum(
            1 for i in incidents
            if not i.fruehwarnung_sent and i.fruehwarnung_deadline
            and i.fruehwarnung_deadline < now
        ),
        'zwischenmeldung_overdue': sum(
            1 for i in incidents
            if not i.zwischenmeldung_sent and i.zwischenmeldung_deadline
            and i.zwischenmeldung_deadline < now
        ),
        'abschlussbericht_overdue': sum(
            1 for i in incidents
            if not i.abschlussbericht_sent and i.abschlussbericht_deadline
            and i.abschlussbericht_deadline < now
        ),
    }
    incidents_summary['reporting_compliant'] = (
        incidents_summary['fruehwarnung_overdue'] == 0
        and incidents_summary['zwischenmeldung_overdue'] == 0
        and incidents_summary['abschlussbericht_overdue'] == 0
    )

    # ── Trainings (§30 Nr. 7 + §38) ──────────────────────────────
    trainings = SecurityTraining.query.filter_by(user_id=user_id).order_by(
        SecurityTraining.created_at.desc()
    ).all()

    gf_acknowledged_count = sum(1 for t in trainings if t.gf_acknowledged)
    total_sent = sum(t.sent_count for t in trainings)
    total_confirmed = sum(t.ack_count for t in trainings)

    trainings_summary = {
        'total': len(trainings),
        'sent': sum(1 for t in trainings if t.status in ('sent', 'closed')),
        'gf_acknowledged': gf_acknowledged_count,
        'gf_pending': len(trainings) - gf_acknowledged_count,
        'total_recipients_sent': total_sent,
        'total_recipients_confirmed': total_confirmed,
        'completion_rate': (
            int(total_confirmed / total_sent * 100) if total_sent > 0 else 0
        ),
    }

    # §38 compliance: at least one training fully acknowledged by GF + sent to staff
    par38_status = (
        'complete' if gf_acknowledged_count > 0 and total_confirmed > 0
        else ('partial' if gf_acknowledged_count > 0
              else 'open')
    )

    # ── Monitoring (§30 Nr. 5, 6) ─────────────────────────────────
    targets = MonitoringTarget.query.filter_by(user_id=user_id).all()
    recent_scans_count = MonitoringScan.query.join(MonitoringTarget).filter(
        MonitoringTarget.user_id == user_id,
        MonitoringScan.scanned_at >= datetime(now.year, 1, 1),
    ).count()

    monitoring_summary = {
        'targets': len(targets),
        'active_targets': sum(1 for t in targets if t.is_active),
        'scans_this_year': recent_scans_count,
        'avg_score': (
            round(sum(t.last_score for t in targets if t.last_score is not None)
                  / max(1, sum(1 for t in targets if t.last_score is not None)), 1)
            if targets else None
        ),
        'targets_below_60': sum(
            1 for t in targets if t.last_score is not None and t.last_score < 60
        ),
    }

    # ── Supply Chain (§30 Nr. 4) ──────────────────────────────────
    suppliers = Supplier.query.filter_by(user_id=user_id, is_active=True).all()
    assessed = [s for s in suppliers if s.last_verification_at]
    avv_signed = [s for s in suppliers if s.avv_exists]
    avv_overdue = [s for s in suppliers if s.avv_overdue]
    high_risk = [s for s in suppliers if s.risk_score and s.risk_score >= 70]

    supply_chain_summary = {
        'total': len(suppliers),
        'assessed': len(assessed),
        'avv_signed': len(avv_signed),
        'avv_overdue': len(avv_overdue),
        'high_risk': len(high_risk),
        'assessment_rate': (
            int(len(assessed) / len(suppliers) * 100) if suppliers else 0
        ),
    }

    # ── Site Audits ───────────────────────────────────────────────
    audit_jobs = NIS2AuditJob.query.filter_by(
        user_id=user_id, status='done'
    ).order_by(NIS2AuditJob.completed_at.desc()).limit(5).all()

    # ── IT Assets ────────────────────────────────────────────────
    assets = ITAsset.query.filter_by(user_id=user_id, is_active=True).all()
    asset_summary = {
        'total': len(assets),
        'critical': sum(1 for a in assets if a.criticality == 'critical'),
        'internet_facing': sum(1 for a in assets if a.is_internet_facing),
        'personal_data': sum(1 for a in assets if a.stores_personal_data),
        'patch_overdue': sum(1 for a in assets if a.patch_overdue),
    }

    # ── Gap analysis ──────────────────────────────────────────────
    gaps = _compute_gaps(
        score_data, bsi_reg, isms_rows, incidents_summary,
        trainings_summary, par38_status, monitoring_summary,
        supply_chain_summary, audit_jobs, asset_summary,
    )

    return {
        'generated_at': now,
        'score_data': score_data,
        'bsi_reg': bsi_reg,
        'isms_rows': isms_rows,
        'isms_complete': isms_complete,
        'isms_total': isms_total,
        'incidents': incidents,
        'incidents_summary': incidents_summary,
        'trainings': trainings,
        'trainings_summary': trainings_summary,
        'par38_status': par38_status,
        'targets': targets,
        'monitoring_summary': monitoring_summary,
        'suppliers': suppliers,
        'supply_chain_summary': supply_chain_summary,
        'audit_jobs': audit_jobs,
        'assets': assets,
        'asset_summary': asset_summary,
        'gaps': gaps,
    }


def _compute_gaps(score_data, bsi_reg, isms_rows, incidents_summary,
                  trainings_summary, par38_status, monitoring_summary,
                  supply_chain_summary, audit_jobs, asset_summary=None) -> list:
    gaps = []

    # §33 BSI Registration
    if not bsi_reg or not bsi_reg.is_complete:
        gaps.append({
            'severity': 'critical',
            'paragraph': '§33 BSIG',
            'title': 'BSI-Registrierung nicht abgeschlossen',
            'description': (
                'Die Registrierung beim BSI-MUK-Portal ist für NIS2-Einrichtungen '
                'Pflicht. Fehlende Registrierung ist eine Ordnungswidrigkeit.'
            ),
            'action': 'BSI-Registrierungsassistenten abschließen',
            'action_url': '/nis2/bsi-registration/',
        })

    # §30 Nr. 1 — Risikoanalyse
    missing_nr1 = [r for r in isms_rows
                   if r['doc_type'] in ('risk_analysis', 'security_policy')
                   and not r['exists']]
    for m in missing_nr1:
        gaps.append({
            'severity': 'high',
            'paragraph': m['paragraph'],
            'title': f'Dokument fehlt: {m["title"]}',
            'description': f'Pflichtdokument nach {m["paragraph"]} BSIG noch nicht erstellt.',
            'action': 'ISMS-Dokument generieren',
            'action_url': '/nis2/isms/',
        })

    # §32 — Incident Reporting
    if incidents_summary['fruehwarnung_overdue'] > 0:
        gaps.append({
            'severity': 'critical',
            'paragraph': '§32 BSIG',
            'title': f'{incidents_summary["fruehwarnung_overdue"]} Frühwarnung(en) überfällig',
            'description': 'Frühwarnungen müssen innerhalb von 24h nach Erkennung an das BSI übermittelt werden.',
            'action': 'Incidents öffnen und BSI-Meldung einreichen',
            'action_url': '/nis2/incidents/',
        })
    if incidents_summary['abschlussbericht_overdue'] > 0:
        gaps.append({
            'severity': 'high',
            'paragraph': '§32 BSIG',
            'title': f'{incidents_summary["abschlussbericht_overdue"]} Abschlussbericht(e) überfällig',
            'description': 'Abschlussberichte müssen innerhalb von 30 Tagen nach Erkennung eingereicht werden.',
            'action': 'Abschlussberichte erstellen',
            'action_url': '/nis2/incidents/',
        })

    # §38 — GF Training Acknowledgment
    if par38_status == 'open':
        gaps.append({
            'severity': 'high',
            'paragraph': '§38 BSIG',
            'title': 'Keine GF-Bestätigung für Schulungen',
            'description': (
                'Geschäftsleiter sind persönlich verpflichtet, Schulungsinhalte '
                'zu lesen und zu billigen (§38 BSIG). Noch keine Bestätigung vorhanden.'
            ),
            'action': 'Schulung lesen und §38-Bestätigung abgeben',
            'action_url': '/nis2/training/',
        })
    elif par38_status == 'partial':
        gaps.append({
            'severity': 'medium',
            'paragraph': '§38 BSIG',
            'title': 'GF-Bestätigung vorhanden, aber keine Mitarbeiter-Schulungen abgeschlossen',
            'description': (
                'Die Schulung wurde von der GF bestätigt, '
                'aber noch kein Mitarbeiter hat die Schulung abgeschlossen.'
            ),
            'action': 'Schulung an Mitarbeiter versenden',
            'action_url': '/nis2/training/',
        })

    # §30 Nr. 4 — Supply Chain
    if supply_chain_summary['total'] == 0:
        gaps.append({
            'severity': 'medium',
            'paragraph': '§30 Nr. 4',
            'title': 'Keine Lieferanten erfasst',
            'description': 'Lieferkettensicherheit erfordert ein Lieferantenregister mit Risikobewertung.',
            'action': 'Lieferanten erfassen und bewerten',
            'action_url': '/nis2/supply-chain/',
        })
    elif supply_chain_summary['avv_overdue'] > 0:
        gaps.append({
            'severity': 'medium',
            'paragraph': '§30 Nr. 4 / DSGVO Art. 28',
            'title': f'{supply_chain_summary["avv_overdue"]} AVV(s) überfällig zur Prüfung',
            'description': 'Auftragsverarbeitungsverträge müssen regelmäßig geprüft und erneuert werden.',
            'action': 'AVV-Status in Lieferkette prüfen',
            'action_url': '/nis2/supply-chain/',
        })

    # §30 Nr. 5 / 6 — Monitoring
    if monitoring_summary['targets'] == 0:
        gaps.append({
            'severity': 'medium',
            'paragraph': '§30 Nr. 5',
            'title': 'Kein Monitoring-Target konfiguriert',
            'description': 'Kontinuierliches Schwachstellenmanagement erfordert regelmäßige automatische Scans.',
            'action': 'Monitoring-Target hinzufügen',
            'action_url': '/nis2/monitoring/',
        })
    elif monitoring_summary['scans_this_year'] < 4:
        gaps.append({
            'severity': 'low',
            'paragraph': '§30 Nr. 6',
            'title': f'Nur {monitoring_summary["scans_this_year"]} Scan(s) dieses Jahr (Empfehlung: ≥4)',
            'description': 'Zur Wirksamkeitsbewertung werden mindestens 4 Scans pro Jahr empfohlen.',
            'action': 'Scan-Frequenz erhöhen',
            'action_url': '/nis2/monitoring/',
        })

    # §30 Nr. 5 / 9 — Asset Inventory
    if asset_summary and asset_summary['total'] == 0:
        gaps.append({
            'severity': 'medium',
            'paragraph': '§30 Nr. 5 / Nr. 9',
            'title': 'Kein IT-Asset-Inventar vorhanden',
            'description': (
                'Ein IT-Asset-Register ist Grundlage für Schwachstellenmanagement (Nr. 5) '
                'und Zugriffskontrolle (Nr. 9) nach §30 BSIG.'
            ),
            'action': 'IT-Assets erfassen',
            'action_url': '/nis2/assets/',
        })
    elif asset_summary and asset_summary['patch_overdue'] > 0:
        gaps.append({
            'severity': 'medium',
            'paragraph': '§30 Nr. 5',
            'title': f'{asset_summary["patch_overdue"]} Asset(s) mit überfälliger Patch-Frist',
            'description': 'Regelmäßiges Patchen ist Bestandteil des Schwachstellenmanagements nach §30 Nr. 5.',
            'action': 'Asset-Inventar öffnen',
            'action_url': '/nis2/assets/',
        })

    # Remaining missing ISMS docs (not already covered above)
    covered_types = {'risk_analysis', 'security_policy'}
    for r in isms_rows:
        if r['doc_type'] not in covered_types and not r['exists']:
            gaps.append({
                'severity': 'medium',
                'paragraph': r['paragraph'],
                'title': f'Dokument fehlt: {r["title"]}',
                'description': f'Empfohlenes Dokument nach {r["paragraph"]} BSIG / {r["bsi_std"]}.',
                'action': 'ISMS-Dokument generieren',
                'action_url': '/nis2/isms/',
            })

    # Sort: critical → high → medium → low
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    gaps.sort(key=lambda g: order.get(g['severity'], 9))
    return gaps
