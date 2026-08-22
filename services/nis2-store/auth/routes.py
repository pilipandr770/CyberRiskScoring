"""
Auth blueprint — Registration, Login, Logout, Email Confirmation, Password Reset, MFA.
"""

import io
import base64
import json
import logging
from datetime import UTC, datetime, timedelta

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app, session,
)
from flask_login import login_user, logout_user, login_required, current_user
from flask_mail import Message

from app.extensions import db, mail, limiter
from app.models import User

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__, template_folder='../templates/auth')


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour')
def register():
    """Public self-service signup — disabled. Access to this platform is
    insurer-gated: accounts are created by the provisioning webhook
    (app/nis2/provisioning.py) once an underwriter accepts a decision in
    Module 2, not by a visitor filling in this form."""
    flash(
        'Der Zugang zu diesem Portal erfolgt über Ihre Cyber-Versicherung — '
        'eine eigenständige Registrierung ist nicht möglich. Bitte wenden Sie '
        'sich an Ihren Versicherungsberater.',
        'info',
    )
    return redirect(url_for('auth.login'))




# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per minute; 100 per hour')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('nis2.dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(password):
            flash('Ungültige E-Mail-Adresse oder Passwort.', 'danger')
            return render_template('auth/login.html')

        if not user.is_active:
            flash('Ihr Konto wurde deaktiviert. Bitte kontaktieren Sie den Support.', 'danger')
            return render_template('auth/login.html')

        # If TOTP is enabled, hold the user ID in session and require code
        if user.totp_enabled:
            session['mfa_user_id'] = user.id
            session['mfa_remember'] = remember
            next_page = request.args.get('next', '')
            session['mfa_next'] = next_page if next_page.startswith('/') else ''
            return redirect(url_for('auth.mfa_verify'))

        user.last_login = datetime.now(UTC)
        db.session.commit()
        login_user(user, remember=remember)

        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('nis2.dashboard'))

    return render_template('auth/login.html')


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sie wurden erfolgreich abgemeldet.', 'info')
    return redirect(url_for('index'))


# ── Email confirmation ────────────────────────────────────────────────────────

@auth_bp.route('/confirm/<token>')
def confirm_email(token):
    user = User.query.filter_by(email_confirmation_token=token).first()
    if not user:
        flash('Ungültiger oder abgelaufener Bestätigungslink.', 'danger')
        return redirect(url_for('auth.login'))

    user.confirm_email()
    db.session.commit()
    flash('E-Mail-Adresse erfolgreich bestätigt!', 'success')
    return redirect(url_for('nis2.dashboard'))


@auth_bp.route('/resend-confirmation')
@login_required
def resend_confirmation():
    if current_user.is_email_confirmed:
        flash('Ihre E-Mail ist bereits bestätigt.', 'info')
        return redirect(url_for('nis2.dashboard'))

    current_user.generate_confirmation_token()
    db.session.commit()
    try:
        _send_confirmation_email(current_user)
        flash('Bestätigungs-E-Mail wurde erneut gesendet.', 'success')
    except Exception as exc:
        logger.warning('Resend confirmation failed: %s', exc)
        flash('E-Mail konnte nicht gesendet werden. Bitte versuchen Sie es später.', 'danger')

    return redirect(url_for('nis2.dashboard'))


# ── Password reset ────────────────────────────────────────────────────────────

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit('5 per hour')
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()

        # Always show same message (prevent enumeration)
        flash(
            'Falls diese E-Mail-Adresse registriert ist, erhalten Sie in Kürze eine E-Mail.',
            'info',
        )

        if user:
            token = user.generate_reset_token()
            db.session.commit()
            try:
                _send_reset_email(user, token)
            except Exception as exc:
                logger.warning('Could not send reset email: %s', exc)

        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(password_reset_token=token).first()
    if not user or not user.is_reset_token_valid(token):
        flash('Ungültiger oder abgelaufener Link. Bitte fordern Sie einen neuen an.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if len(password) < 8:
            flash('Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        if password != password2:
            flash('Passwörter stimmen nicht überein.', 'danger')
            return render_template('auth/reset_password.html', token=token)

        user.set_password(password)
        user.password_reset_token = None
        user.password_reset_expires = None
        db.session.commit()

        flash('Passwort wurde erfolgreich geändert. Bitte melden Sie sich an.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token)


# ── Profile ───────────────────────────────────────────────────────────────────

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        from app.input_guard import trunc
        current_user.first_name  = trunc(request.form.get('first_name', ''),  100, field='first_name')
        current_user.last_name   = trunc(request.form.get('last_name', ''),   100, field='last_name')
        current_user.company_name = trunc(request.form.get('company_name', ''), 200, field='company_name')
        current_user.phone       = trunc(request.form.get('phone', ''),        50,  field='phone')

        new_password = request.form.get('new_password', '')[:128]
        if new_password:
            if len(new_password) < 8:
                flash('Neues Passwort muss mindestens 8 Zeichen lang sein.', 'danger')
                return render_template('auth/profile.html')
            current_user.set_password(new_password)

        db.session.commit()
        flash('Profil erfolgreich aktualisiert.', 'success')
        return redirect(url_for('auth.profile'))

    return render_template('auth/profile.html')


# ── MFA / TOTP ────────────────────────────────────────────────────────────────

@auth_bp.route('/mfa/verify', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def mfa_verify():
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = db.session.get(User, user_id)
    if not user:
        session.pop('mfa_user_id', None)
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip().replace(' ', '')

        verified = False
        used_backup = False

        if len(code) == 6 and code.isdigit():
            verified = user.verify_totp(code)
        elif len(code) == 8:  # backup code format XXXXXXXX
            verified = user.use_backup_code(code)
            used_backup = verified

        if verified:
            if used_backup:
                db.session.commit()  # save consumed backup code
            remember = session.pop('mfa_remember', False)
            next_page = session.pop('mfa_next', '')
            session.pop('mfa_user_id', None)
            user.last_login = datetime.now(UTC)
            db.session.commit()
            login_user(user, remember=remember)
            if used_backup:
                flash('Backup-Code verwendet. Bitte generieren Sie neue Codes.', 'warning')
            return redirect(next_page or url_for('nis2.dashboard'))

        flash('Ungültiger Code. Bitte versuchen Sie es erneut.', 'danger')

    return render_template('auth/mfa_verify.html')


@auth_bp.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not current_user.totp_secret:
            flash('Kein TOTP-Secret gesetzt. Bitte neu laden.', 'danger')
            return redirect(url_for('auth.mfa_setup'))

        if current_user.verify_totp(code):
            current_user.totp_enabled = True
            backup_codes = current_user.generate_backup_codes()
            db.session.commit()
            flash('Zwei-Faktor-Authentifizierung erfolgreich aktiviert!', 'success')
            return render_template('auth/mfa_backup_codes.html', backup_codes=backup_codes)

        flash('Ungültiger Code — bitte erneut scannen und versuchen.', 'danger')

    # Generate a fresh secret only on GET (not after a failed POST — would invalidate already-scanned QR)
    if request.method == 'GET' and not current_user.totp_enabled:
        current_user.generate_totp_secret()
        db.session.commit()

    totp_uri = current_user.get_totp_uri()
    qr_image_b64 = _generate_qr_b64(totp_uri)

    return render_template('auth/mfa_setup.html',
                           totp_uri=totp_uri,
                           qr_image_b64=qr_image_b64,
                           secret=current_user.totp_secret)


@auth_bp.route('/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    code = request.form.get('code', '').strip()
    if not current_user.verify_totp(code):
        flash('Ungültiger TOTP-Code. MFA wurde nicht deaktiviert.', 'danger')
        return redirect(url_for('auth.profile'))

    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.totp_backup_codes_json = None
    db.session.commit()
    flash('Zwei-Faktor-Authentifizierung wurde deaktiviert.', 'info')
    return redirect(url_for('auth.profile'))


def _generate_qr_b64(uri: str) -> str:
    import qrcode
    qr = qrcode.QRCode(box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode('ascii')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _send_confirmation_email(user: User):
    token = user.email_confirmation_token
    confirm_url = url_for('auth.confirm_email', token=token, _external=True)
    msg = Message(
        subject='NIS2 Compliance — E-Mail bestätigen',
        recipients=[user.email],
        html=render_template('auth/email_confirm.html',
                             user=user, confirm_url=confirm_url),
    )
    mail.send(msg)


def _send_reset_email(user: User, token: str):
    reset_url = url_for('auth.reset_password', token=token, _external=True)
    msg = Message(
        subject='NIS2 Compliance — Passwort zurücksetzen',
        recipients=[user.email],
        html=render_template('auth/email_reset.html',
                             user=user, reset_url=reset_url),
    )
    mail.send(msg)
