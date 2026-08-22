"""
Payments blueprint — Stripe removed. Access to this platform is insurer-
gated (provisioned via Module 2's underwriter decision, see
app/nis2/provisioning.py), not sold as a self-service paid tier. Routes
kept as harmless stubs so existing nav links/templates referencing
`payments.pricing` / `payments.cancel_subscription` don't 404 while those
templates get cleaned up.
"""

from flask import Blueprint, flash, redirect, render_template, url_for
from flask_login import login_required

payments_bp = Blueprint('payments', __name__, template_folder='../templates/payments')


@payments_bp.route('/pricing')
def pricing():
    return render_template('payments/pricing.html')


@payments_bp.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    flash('Ihr Zugang ist Teil Ihres Versicherungsschutzes und wird nicht über dieses Portal verwaltet.', 'info')
    return redirect(url_for('auth.profile'))
