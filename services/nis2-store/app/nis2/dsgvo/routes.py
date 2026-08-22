"""
DSGVO Art. 30 — Verarbeitungsverzeichnis (VVT)

Processing activities register as required by GDPR Art. 30. Tracks all personal
data processing activities, legal bases, retention periods, and TOMs.
Parallel requirement to NIS2 — incidents triggering §32 reporting often also
trigger DSGVO Art. 33 notifications, so both registers should be maintained.
"""

from datetime import UTC, date, datetime

from flask import flash, make_response, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from ..models import (
    ProcessingActivity, Supplier,
    LEGAL_BASES, DATA_CATEGORIES_OPTIONS, DATA_SUBJECT_TYPES,
)

import json


def register_dsgvo_routes(bp):

    # ── List ──────────────────────────────────────────────────────
    @bp.route('/dsgvo/art30/')
    @login_required
    def dsgvo_list():
        activities = (ProcessingActivity.query
                      .filter_by(user_id=current_user.id, is_active=True)
                      .order_by(ProcessingActivity.name)
                      .all())
        stats = {
            'total': len(activities),
            'high_risk': sum(1 for a in activities if a.is_high_risk),
            'third_country': sum(1 for a in activities if a.third_country_transfer),
            'review_overdue': sum(1 for a in activities if a.review_overdue),
            'dsfa_needed': sum(1 for a in activities if a.is_high_risk and not a.dsfa_done),
        }
        return render_template('nis2/dsgvo/list.html',
                               activities=activities, stats=stats,
                               legal_bases=LEGAL_BASES)

    # ── Create ────────────────────────────────────────────────────
    @bp.route('/dsgvo/art30/new', methods=['GET', 'POST'])
    @login_required
    def dsgvo_create():
        suppliers = Supplier.query.filter_by(user_id=current_user.id, is_active=True).all()
        if request.method == 'POST':
            act = ProcessingActivity(user_id=current_user.id)
            _populate(act, request.form)
            db.session.add(act)
            db.session.commit()
            flash(f'Verarbeitungstätigkeit „{act.name}" gespeichert.', 'success')
            return redirect(url_for('nis2.dsgvo_list'))
        return render_template('nis2/dsgvo/form.html',
                               activity=None, suppliers=suppliers,
                               legal_bases=LEGAL_BASES,
                               data_categories=DATA_CATEGORIES_OPTIONS,
                               data_subjects=DATA_SUBJECT_TYPES)

    # ── Edit ──────────────────────────────────────────────────────
    @bp.route('/dsgvo/art30/<int:activity_id>/edit', methods=['GET', 'POST'])
    @login_required
    def dsgvo_edit(activity_id):
        act = ProcessingActivity.query.filter_by(
            id=activity_id, user_id=current_user.id
        ).first_or_404()
        suppliers = Supplier.query.filter_by(user_id=current_user.id, is_active=True).all()
        if request.method == 'POST':
            _populate(act, request.form)
            db.session.commit()
            flash('Verarbeitungstätigkeit aktualisiert.', 'success')
            return redirect(url_for('nis2.dsgvo_list'))
        return render_template('nis2/dsgvo/form.html',
                               activity=act, suppliers=suppliers,
                               legal_bases=LEGAL_BASES,
                               data_categories=DATA_CATEGORIES_OPTIONS,
                               data_subjects=DATA_SUBJECT_TYPES)

    # ── Delete ────────────────────────────────────────────────────
    @bp.route('/dsgvo/art30/<int:activity_id>/delete', methods=['POST'])
    @login_required
    def dsgvo_delete(activity_id):
        act = ProcessingActivity.query.filter_by(
            id=activity_id, user_id=current_user.id
        ).first_or_404()
        act.is_active = False
        db.session.commit()
        flash(f'„{act.name}" archiviert.', 'info')
        return redirect(url_for('nis2.dsgvo_list'))

    # ── Export HTML ───────────────────────────────────────────────
    @bp.route('/dsgvo/art30/export')
    @login_required
    def dsgvo_export():
        activities = (ProcessingActivity.query
                      .filter_by(user_id=current_user.id, is_active=True)
                      .order_by(ProcessingActivity.name)
                      .all())
        html = render_template('nis2/dsgvo/export.html',
                               activities=activities,
                               generated_at=datetime.now(UTC),
                               user=current_user)
        resp = make_response(html)
        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
        resp.headers['Content-Disposition'] = (
            f'attachment; filename="VVT-Art30-{datetime.now(UTC).strftime("%Y%m%d")}.html"'
        )
        return resp


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _populate(act: ProcessingActivity, form) -> None:
    act.name = form.get('name', '').strip()
    act.purpose = form.get('purpose', '').strip()
    act.legal_basis = form.get('legal_basis', '') or None
    act.legal_basis_notes = form.get('legal_basis_notes', '').strip() or None

    # Multi-select lists
    act.data_categories_json = json.dumps(form.getlist('data_categories') or [],
                                          ensure_ascii=False)
    act.data_subject_types_json = json.dumps(form.getlist('data_subjects') or [],
                                             ensure_ascii=False)

    act.recipients = form.get('recipients', '').strip() or None
    act.third_country_transfer = bool(form.get('third_country_transfer'))
    act.third_country_safeguards = form.get('third_country_safeguards', '').strip() or None
    act.retention_period = form.get('retention_period', '').strip() or None
    act.deletion_process = form.get('deletion_process', '').strip() or None
    act.technical_measures = form.get('technical_measures', '').strip() or None

    proc_id = form.get('processor_id', '').strip()
    act.processor_id = int(proc_id) if proc_id else None
    act.processor_name = form.get('processor_name', '').strip() or None

    act.is_high_risk = bool(form.get('is_high_risk'))
    act.dsfa_done = bool(form.get('dsfa_done'))
    act.notes = form.get('notes', '').strip() or None

    review = form.get('next_review_date', '').strip()
    act.next_review_date = date.fromisoformat(review) if review else None
    act.last_reviewed_at = datetime.now(UTC)
