"""
Fristenkalender — Unified deadline tracker (§32 BSIG + §33 + patch + AVV + ISMS reviews).

Collects all time-sensitive compliance obligations across all modules and
presents them in a single prioritised view, colour-coded by urgency.
"""

from datetime import date, datetime, timedelta

from flask import render_template
from flask_login import current_user, login_required

from ..models import (
    Incident, SecurityTraining,
    MonitoringTarget, ISMSDocument,
    Supplier, ITAsset,
    ProcessingActivity, Risk,
)


def register_deadline_routes(bp):

    @bp.route('/fristen/')
    @login_required
    def fristen():
        items = _collect_deadlines(current_user.id)
        today = date.today()

        overdue = [i for i in items if i['due_date'] < today]
        due_soon = [i for i in items if today <= i['due_date'] <= today + timedelta(days=30)]
        upcoming = [i for i in items if i['due_date'] > today + timedelta(days=30)]

        return render_template(
            'nis2/deadlines/index.html',
            overdue=overdue, due_soon=due_soon, upcoming=upcoming,
            today=today,
        )


# ─────────────────────────────────────────────────────────────────
# Data collection
# ─────────────────────────────────────────────────────────────────

def _collect_deadlines(user_id: int) -> list:
    today = date.today()
    items = []

    # ── §32 BSIG — Incident reporting deadlines ──────────────────
    incidents = Incident.query.filter_by(user_id=user_id).filter(
        Incident.status.in_(['open', 'contained', 'eradicated'])
    ).all()

    for inc in incidents:
        if inc.fruehwarnung_deadline and not inc.fruehwarnung_sent:
            items.append({
                'title': f'Frühwarnung (24h): {inc.title}',
                'due_date': inc.fruehwarnung_deadline.date(),
                'category': '§32 BSIG',
                'severity': 'critical',
                'url': f'/nis2/incidents/{inc.id}',
                'icon': 'bi-alarm',
                'ref': inc.incident_ref or f'INC-{inc.id}',
            })
        if inc.zwischenmeldung_deadline and not inc.zwischenmeldung_sent:
            items.append({
                'title': f'Zwischenmeldung (72h): {inc.title}',
                'due_date': inc.zwischenmeldung_deadline.date(),
                'category': '§32 BSIG',
                'severity': 'critical',
                'url': f'/nis2/incidents/{inc.id}',
                'icon': 'bi-clock-history',
                'ref': inc.incident_ref or f'INC-{inc.id}',
            })
        if inc.abschlussbericht_deadline and not inc.abschlussbericht_sent:
            items.append({
                'title': f'Abschlussbericht (30d): {inc.title}',
                'due_date': inc.abschlussbericht_deadline.date(),
                'category': '§32 BSIG',
                'severity': 'high',
                'url': f'/nis2/incidents/{inc.id}',
                'icon': 'bi-file-earmark-text',
                'ref': inc.incident_ref or f'INC-{inc.id}',
            })

    # ── ISMS document reviews ─────────────────────────────────────
    docs = ISMSDocument.query.filter_by(user_id=user_id, is_generated=True).filter(
        ISMSDocument.next_review_date.isnot(None)
    ).all()
    for doc in docs:
        if doc.next_review_date:
            items.append({
                'title': f'ISMS-Dokument Überprüfung: {doc.title or doc.doc_type}',
                'due_date': doc.next_review_date,
                'category': '§30 Nr. 1',
                'severity': 'high' if doc.review_overdue else 'medium',
                'url': f'/nis2/isms/documents/{doc.id}',
                'icon': 'bi-file-earmark-check',
                'ref': doc.nis2_paragraph_ref or doc.doc_type,
            })

    # ── Supply Chain — AVV reviews ────────────────────────────────
    suppliers = Supplier.query.filter_by(user_id=user_id, is_active=True).filter(
        Supplier.avv_review_due.isnot(None)
    ).all()
    for s in suppliers:
        if s.avv_review_due:
            items.append({
                'title': f'AVV Überprüfung: {s.company_name}',
                'due_date': s.avv_review_due,
                'category': '§30 Nr. 4 / DSGVO Art. 28',
                'severity': 'high' if s.avv_overdue else 'medium',
                'url': f'/nis2/supply-chain/{s.id}',
                'icon': 'bi-file-earmark-ruled',
                'ref': s.company_name[:30],
            })

    # ── IT Assets — patch deadlines ───────────────────────────────
    assets = ITAsset.query.filter_by(user_id=user_id, is_active=True).filter(
        ITAsset.next_patch_due.isnot(None)
    ).all()
    for a in assets:
        if a.next_patch_due:
            items.append({
                'title': f'Patch fällig: {a.name}',
                'due_date': a.next_patch_due,
                'category': '§30 Nr. 5',
                'severity': 'high' if a.patch_overdue else 'medium',
                'url': f'/nis2/assets/{a.id}/edit',
                'icon': 'bi-patch-exclamation',
                'ref': a.category_label,
            })

    # ── Training due dates ────────────────────────────────────────
    trainings = SecurityTraining.query.filter_by(user_id=user_id).filter(
        SecurityTraining.due_date.isnot(None),
        SecurityTraining.status != 'closed',
    ).all()
    for t in trainings:
        if t.due_date:
            items.append({
                'title': f'Schulungsfrist: {t.title}',
                'due_date': t.due_date,
                'category': '§30 Nr. 7',
                'severity': 'medium' if t.due_date < today else 'low',
                'url': f'/nis2/training/{t.id}',
                'icon': 'bi-mortarboard',
                'ref': t.topic_label,
            })

    # ── Risk reviews ──────────────────────────────────────────────
    risks = Risk.query.filter_by(user_id=user_id).filter(
        Risk.review_date.isnot(None),
        Risk.status != 'closed',
    ).all()
    for r in risks:
        if r.review_date:
            items.append({
                'title': f'Risiko-Review: {r.title}',
                'due_date': r.review_date,
                'category': '§30 Nr. 1',
                'severity': 'high' if r.review_overdue and r.risk_level in ('critical', 'high') else 'low',
                'url': f'/nis2/risk-register/{r.id}/edit',
                'icon': 'bi-shield-exclamation',
                'ref': f'Score: {r.risk_score}',
            })

    # ── DSGVO VVT reviews ─────────────────────────────────────────
    activities = ProcessingActivity.query.filter_by(user_id=user_id, is_active=True).filter(
        ProcessingActivity.next_review_date.isnot(None)
    ).all()
    for act in activities:
        if act.next_review_date:
            items.append({
                'title': f'VVT-Review: {act.name}',
                'due_date': act.next_review_date,
                'category': 'DSGVO Art. 30',
                'severity': 'medium' if act.review_overdue else 'low',
                'url': f'/nis2/dsgvo/art30/{act.id}/edit',
                'icon': 'bi-person-lock',
                'ref': 'Art. 30 DSGVO',
            })

    # ── Monitoring: targets with no scan in 90 days ───────────────
    stale_limit = today - timedelta(days=90)
    targets = MonitoringTarget.query.filter_by(user_id=user_id, is_active=True).all()
    for t in targets:
        if not t.last_scan_at or t.last_scan_at.date() < stale_limit:
            next_due = (t.last_scan_at.date() + timedelta(days=90)) if t.last_scan_at else today
            items.append({
                'title': f'Monitoring-Scan überfällig: {t.domain}',
                'due_date': next_due,
                'category': '§30 Nr. 5 / 6',
                'severity': 'medium',
                'url': f'/nis2/monitoring/targets/{t.id}',
                'icon': 'bi-radar',
                'ref': t.domain[:40],
            })

    # Sort by due_date ascending
    items.sort(key=lambda x: x['due_date'])
    return items
