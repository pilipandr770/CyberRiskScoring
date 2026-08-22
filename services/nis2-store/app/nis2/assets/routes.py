"""
IT Asset Inventory — Routes (§30 Nr. 5 + Nr. 9 BSIG)

Provides a register of IT assets (servers, cloud services, workstations, software, etc.)
with patch-status tracking, criticality classification, and DSGVO Art. 30 tagging
(assets storing personal data). Used as evidence for §30 Nr. 5 (Schwachstellenmanagement)
and Nr. 9 (Zugriffskontrolle / Asset-Management).
"""

from datetime import date

from flask import (abort, flash, redirect, render_template, request, url_for)
from flask_login import current_user, login_required

from app.extensions import db
from ..models import ITAsset, ASSET_CATEGORIES, ASSET_CRITICALITIES


def register_asset_routes(bp):

    # ── List ──────────────────────────────────────────────────────
    @bp.route('/assets/')
    @login_required
    def asset_list():
        assets = (
            ITAsset.query
            .filter_by(user_id=current_user.id, is_active=True)
            .order_by(ITAsset.criticality.asc(), ITAsset.name.asc())
            .all()
        )
        stats = _asset_stats(assets)
        return render_template('nis2/assets/list.html',
                               assets=assets, stats=stats,
                               categories=ASSET_CATEGORIES,
                               criticalities=ASSET_CRITICALITIES)

    # ── Create ────────────────────────────────────────────────────
    @bp.route('/assets/new', methods=['GET', 'POST'])
    @login_required
    def asset_create():
        if request.method == 'POST':
            asset = ITAsset(user_id=current_user.id)
            _populate_asset(asset, request.form)
            db.session.add(asset)
            db.session.commit()
            flash(f'Asset „{asset.name}" erfolgreich angelegt.', 'success')
            return redirect(url_for('nis2.asset_list'))
        return render_template('nis2/assets/form.html',
                               asset=None,
                               categories=ASSET_CATEGORIES,
                               criticalities=ASSET_CRITICALITIES,
                               today=date.today())

    # ── Edit ──────────────────────────────────────────────────────
    @bp.route('/assets/<int:asset_id>/edit', methods=['GET', 'POST'])
    @login_required
    def asset_edit(asset_id):
        asset = ITAsset.query.filter_by(
            id=asset_id, user_id=current_user.id
        ).first_or_404()
        if request.method == 'POST':
            _populate_asset(asset, request.form)
            db.session.commit()
            flash('Asset aktualisiert.', 'success')
            return redirect(url_for('nis2.asset_list'))
        return render_template('nis2/assets/form.html',
                               asset=asset,
                               categories=ASSET_CATEGORIES,
                               criticalities=ASSET_CRITICALITIES,
                               today=date.today())

    # ── Delete ────────────────────────────────────────────────────
    @bp.route('/assets/<int:asset_id>/delete', methods=['POST'])
    @login_required
    def asset_delete(asset_id):
        asset = ITAsset.query.filter_by(
            id=asset_id, user_id=current_user.id
        ).first_or_404()
        # Soft-delete
        asset.is_active = False
        db.session.commit()
        flash(f'Asset „{asset.name}" archiviert.', 'info')
        return redirect(url_for('nis2.asset_list'))

    # ── Mark patched ──────────────────────────────────────────────
    @bp.route('/assets/<int:asset_id>/mark-patched', methods=['POST'])
    @login_required
    def asset_mark_patched(asset_id):
        asset = ITAsset.query.filter_by(
            id=asset_id, user_id=current_user.id
        ).first_or_404()
        asset.last_patched_at = date.today()
        asset.patch_status = 'current'
        db.session.commit()
        flash(f'„{asset.name}" als gepatcht markiert.', 'success')
        return redirect(url_for('nis2.asset_list'))


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _populate_asset(asset: ITAsset, form) -> None:
    asset.name = form.get('name', '').strip()
    asset.asset_type = form.get('asset_type', 'other')
    asset.description = form.get('description', '').strip() or None
    asset.vendor = form.get('vendor', '').strip() or None
    asset.version = form.get('version', '').strip() or None
    asset.serial_number = form.get('serial_number', '').strip() or None
    asset.ip_address = form.get('ip_address', '').strip() or None
    asset.hostname = form.get('hostname', '').strip() or None
    asset.location = form.get('location', '').strip() or None
    asset.owner_name = form.get('owner_name', '').strip() or None
    asset.owner_email = form.get('owner_email', '').strip() or None
    asset.department = form.get('department', '').strip() or None
    asset.criticality = form.get('criticality', 'medium')
    asset.is_internet_facing = bool(form.get('is_internet_facing'))
    asset.stores_personal_data = bool(form.get('stores_personal_data'))
    asset.patch_status = form.get('patch_status', 'unknown')
    asset.known_vulnerabilities = form.get('known_vulnerabilities', '').strip() or None
    asset.notes = form.get('notes', '').strip() or None

    last_patched = form.get('last_patched_at', '').strip()
    asset.last_patched_at = _parse_date(last_patched)

    next_patch = form.get('next_patch_due', '').strip()
    asset.next_patch_due = _parse_date(next_patch)


def _parse_date(value: str):
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _asset_stats(assets: list) -> dict:
    total = len(assets)
    by_criticality = {
        'critical': sum(1 for a in assets if a.criticality == 'critical'),
        'high': sum(1 for a in assets if a.criticality == 'high'),
        'medium': sum(1 for a in assets if a.criticality == 'medium'),
        'low': sum(1 for a in assets if a.criticality == 'low'),
    }
    internet_facing = sum(1 for a in assets if a.is_internet_facing)
    personal_data = sum(1 for a in assets if a.stores_personal_data)
    patch_overdue = sum(1 for a in assets if a.patch_overdue)
    outdated = sum(1 for a in assets if a.patch_status == 'outdated')
    return {
        'total': total,
        'by_criticality': by_criticality,
        'internet_facing': internet_facing,
        'personal_data': personal_data,
        'patch_overdue': patch_overdue,
        'outdated': outdated,
        'needs_attention': patch_overdue + outdated,
    }
