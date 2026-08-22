"""
Legal pages blueprint — Impressum, AGB, Datenschutz, Konto löschen.
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import current_user, login_required

from app.extensions import db

legal_bp = Blueprint('legal', __name__, template_folder='../templates/legal')


@legal_bp.route('/impressum')
def impressum():
    return render_template('legal/impressum.html')


@legal_bp.route('/agb')
def agb():
    return render_template('legal/agb.html')


@legal_bp.route('/datenschutz')
def datenschutz():
    return render_template('legal/datenschutz.html')


@legal_bp.route('/konto-loeschen', methods=['GET', 'POST'])
@login_required
def delete_account():
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if confirm != 'LÖSCHEN':
            flash('Bitte geben Sie "LÖSCHEN" zur Bestätigung ein.', 'danger')
            return render_template('legal/delete_account.html')

        if not current_user.check_password(password):
            flash('Falsches Passwort. Konto wurde nicht gelöscht.', 'danger')
            return render_template('legal/delete_account.html')

        from flask_login import logout_user
        user = current_user._get_current_object()
        logout_user()
        db.session.delete(user)
        db.session.commit()
        flash('Ihr Konto wurde vollständig gelöscht. Auf Wiedersehen.', 'info')
        return redirect(url_for('index'))

    return render_template('legal/delete_account.html')
