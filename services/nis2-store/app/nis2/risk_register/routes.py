"""
Risikoregister — Routes (§30 Nr. 1 BSIG / BSI 200-3)

Structured risk register with 5×5 likelihood/impact matrix, treatment plans,
and risk owner tracking. Generates evidence for §30 Nr. 1 (Risikoanalyse) and
is referenced in the §39 compliance report.
"""

from datetime import date

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from ..models import (
    Risk, ITAsset,
    RISK_CATEGORIES, RISK_STATUSES, TREATMENT_TYPES,
)


# Axis labels for the 5×5 matrix display
LIKELIHOOD_LABELS = {
    1: 'Sehr selten', 2: 'Selten', 3: 'Möglich', 4: 'Wahrscheinlich', 5: 'Sehr häufig'
}
IMPACT_LABELS = {
    1: 'Gering', 2: 'Niedrig', 3: 'Mittel', 4: 'Hoch', 5: 'Existenziell'
}


def register_risk_routes(bp):

    # ── List / Matrix ─────────────────────────────────────────────
    @bp.route('/risk-register/')
    @login_required
    def risk_list():
        risks = (Risk.query
                 .filter_by(user_id=current_user.id)
                 .filter(Risk.status != 'closed')
                 .order_by(db.desc(Risk.likelihood * Risk.impact))
                 .all())
        closed = Risk.query.filter_by(user_id=current_user.id, status='closed').count()
        stats = _risk_stats(risks)
        matrix = _build_matrix(risks)
        assets = ITAsset.query.filter_by(user_id=current_user.id, is_active=True).all()
        return render_template(
            'nis2/risk_register/list.html',
            risks=risks, closed=closed, stats=stats, matrix=matrix,
            categories=RISK_CATEGORIES, statuses=RISK_STATUSES,
            likelihood_labels=LIKELIHOOD_LABELS, impact_labels=IMPACT_LABELS,
            assets=assets,
        )

    # ── Create ────────────────────────────────────────────────────
    @bp.route('/risk-register/new', methods=['GET', 'POST'])
    @login_required
    def risk_create():
        assets = ITAsset.query.filter_by(user_id=current_user.id, is_active=True).all()
        if request.method == 'POST':
            risk = Risk(user_id=current_user.id)
            _populate(risk, request.form)
            db.session.add(risk)
            db.session.commit()
            flash(f'Risiko „{risk.title}" erfasst.', 'success')
            return redirect(url_for('nis2.risk_list'))
        return render_template(
            'nis2/risk_register/form.html',
            risk=None, assets=assets,
            categories=RISK_CATEGORIES, treatment_types=TREATMENT_TYPES,
            likelihood_labels=LIKELIHOOD_LABELS, impact_labels=IMPACT_LABELS,
        )

    # ── Edit ──────────────────────────────────────────────────────
    @bp.route('/risk-register/<int:risk_id>/edit', methods=['GET', 'POST'])
    @login_required
    def risk_edit(risk_id):
        risk = Risk.query.filter_by(id=risk_id, user_id=current_user.id).first_or_404()
        assets = ITAsset.query.filter_by(user_id=current_user.id, is_active=True).all()
        if request.method == 'POST':
            _populate(risk, request.form)
            db.session.commit()
            flash('Risiko aktualisiert.', 'success')
            return redirect(url_for('nis2.risk_list'))
        return render_template(
            'nis2/risk_register/form.html',
            risk=risk, assets=assets,
            categories=RISK_CATEGORIES, treatment_types=TREATMENT_TYPES,
            likelihood_labels=LIKELIHOOD_LABELS, impact_labels=IMPACT_LABELS,
        )

    # ── Close ─────────────────────────────────────────────────────
    @bp.route('/risk-register/<int:risk_id>/close', methods=['POST'])
    @login_required
    def risk_close(risk_id):
        risk = Risk.query.filter_by(id=risk_id, user_id=current_user.id).first_or_404()
        risk.status = 'closed'
        db.session.commit()
        flash(f'Risiko „{risk.title}" geschlossen.', 'info')
        return redirect(url_for('nis2.risk_list'))

    # ── Delete ────────────────────────────────────────────────────
    @bp.route('/risk-register/<int:risk_id>/delete', methods=['POST'])
    @login_required
    def risk_delete(risk_id):
        risk = Risk.query.filter_by(id=risk_id, user_id=current_user.id).first_or_404()
        db.session.delete(risk)
        db.session.commit()
        flash('Risiko gelöscht.', 'info')
        return redirect(url_for('nis2.risk_list'))


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _populate(risk: Risk, form) -> None:
    risk.title = form.get('title', '').strip()
    risk.description = form.get('description', '').strip() or None
    risk.category = form.get('category', 'other')
    risk.affected_asset = form.get('affected_asset', '').strip() or None
    asset_id = form.get('asset_id', '').strip()
    risk.asset_id = int(asset_id) if asset_id else None
    risk.likelihood = _int(form.get('likelihood'), 3)
    risk.impact = _int(form.get('impact'), 3)
    risk.treatment_type = form.get('treatment_type', 'mitigate')
    risk.treatment_plan = form.get('treatment_plan', '').strip() or None
    risk.residual_likelihood = _int(form.get('residual_likelihood'), None)
    risk.residual_impact = _int(form.get('residual_impact'), None)
    risk.risk_owner = form.get('risk_owner', '').strip() or None
    risk.nis2_ref = form.get('nis2_ref', '').strip() or None
    risk.status = form.get('status', 'open')
    review = form.get('review_date', '').strip()
    risk.review_date = date.fromisoformat(review) if review else None


def _int(val, default):
    try:
        return int(val) if val else default
    except (ValueError, TypeError):
        return default


def _risk_stats(risks: list) -> dict:
    return {
        'total': len(risks),
        'critical': sum(1 for r in risks if r.risk_level == 'critical'),
        'high': sum(1 for r in risks if r.risk_level == 'high'),
        'medium': sum(1 for r in risks if r.risk_level == 'medium'),
        'low': sum(1 for r in risks if r.risk_level == 'low'),
        'overdue_review': sum(1 for r in risks if r.review_overdue),
        'no_treatment': sum(1 for r in risks if not r.treatment_plan),
    }


def _build_matrix(risks: list) -> list[list]:
    """Returns 5×5 matrix (row=impact desc, col=likelihood asc) with risk counts."""
    matrix = []
    for impact in range(5, 0, -1):
        row = []
        for likelihood in range(1, 6):
            cell_risks = [r for r in risks
                          if r.likelihood == likelihood and r.impact == impact]
            row.append({'likelihood': likelihood, 'impact': impact,
                        'risks': cell_risks, 'count': len(cell_risks)})
        matrix.append(row)
    return matrix
