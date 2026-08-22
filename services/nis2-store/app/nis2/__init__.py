"""
NIS2 Compliance Platform — Main Blueprint

Modular compliance suite for NIS2UmsuCG (since 6 Dec 2025, Germany).
Covers §30 Abs. 2 BSIG (10 measures) + §32/§33/§38/§39 obligations.
"""

from flask import Blueprint, redirect, url_for, flash, request
from flask_login import current_user

nis2_bp = Blueprint(
    'nis2',
    __name__,
    url_prefix='/nis2',
    template_folder='../../templates/nis2',
)


@nis2_bp.before_request
def require_access():
    """Allow only authenticated users with active access (trial or paid plan)."""
    if request.endpoint and 'training_ack' in request.endpoint:
        return None

    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if not current_user.has_access:
        flash(
            'Ihr Testzeitraum ist abgelaufen. Bitte wählen Sie einen Tarif, '
            'um weiterhin Zugang zur NIS2 Compliance Platform zu haben.',
            'warning',
        )
        return redirect(url_for('payments.pricing'))


from .dashboard import register_dashboard_routes
register_dashboard_routes(nis2_bp)

from .bsi_registration.routes import register_bsi_routes
register_bsi_routes(nis2_bp)

from .continuous_monitoring.routes import register_monitoring_routes
register_monitoring_routes(nis2_bp)

from .isms_docs.routes import register_isms_routes
register_isms_routes(nis2_bp)

from .incident_response.routes import register_incident_routes
register_incident_routes(nis2_bp)

from .supply_chain.routes import register_supply_chain_routes
register_supply_chain_routes(nis2_bp)

from .training.routes import register_training_routes
register_training_routes(nis2_bp)

from .site_audit.routes import register_site_audit_routes
register_site_audit_routes(nis2_bp)

from .compliance_report.routes import register_compliance_report_routes
register_compliance_report_routes(nis2_bp)

from .assets.routes import register_asset_routes
register_asset_routes(nis2_bp)

from .risk_register.routes import register_risk_routes
register_risk_routes(nis2_bp)

from .dsgvo.routes import register_dsgvo_routes
register_dsgvo_routes(nis2_bp)

from .deadlines.routes import register_deadline_routes
register_deadline_routes(nis2_bp)
