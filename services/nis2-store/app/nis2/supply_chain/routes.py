"""
Supply Chain — Routes

Supplier register + risk scoring + AVV tracker.
Reuses services/vies.py for VAT validation and services/sanctions.py for screening.
"""

import csv
import io
import json
import logging
from datetime import UTC, datetime

from flask import (abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from services.security_helpers import require_plan
from flask_login import current_user, login_required

from app.extensions import db, limiter
from ..models import Supplier, SupplierAssessment, SUPPLIER_CATEGORIES

logger = logging.getLogger(__name__)


def register_supply_chain_routes(bp):

    # ── Dashboard ─────────────────────────────────────────────────
    @bp.route('/supply-chain/')
    @login_required
    @require_plan("professional")
    def supply_chain_dashboard():
        suppliers = Supplier.query.filter_by(user_id=current_user.id)\
            .order_by(Supplier.risk_score.desc()).all()

        stats = {
            'total': len(suppliers),
            'high_risk': sum(1 for s in suppliers if s.risk_score and s.risk_score >= 70),
            'avv_overdue': sum(1 for s in suppliers if s.avv_overdue),
            'critical': sum(1 for s in suppliers if s.criticality == 'critical'),
        }
        return render_template('nis2/supply_chain/dashboard.html',
                               suppliers=suppliers,
                               stats=stats,
                               categories=SUPPLIER_CATEGORIES)

    # ── Add supplier ──────────────────────────────────────────────
    @bp.route('/supply-chain/add', methods=['GET', 'POST'])
    @login_required
    @require_plan("professional")
    @limiter.limit('60 per hour', methods=['POST'])
    def supply_chain_add():
        if request.method == 'POST':
            from app.input_guard import trunc, trunc_text
            supplier = Supplier(
                user_id=current_user.id,
                company_name=trunc(request.form.get('company_name', ''), 300, field='company_name'),
                category=trunc(request.form.get('category', 'other'), 50, field='category'),
                criticality=trunc(request.form.get('criticality', 'medium'), 20, field='criticality'),
                country=trunc(request.form.get('country', ''), 100, field='country'),
                vat_id=trunc(request.form.get('vat_number', ''), 30, field='vat_id'),
                contact_email=trunc(request.form.get('contact_email', ''), 120, field='contact_email'),
                services_provided=trunc_text(request.form.get('services_provided', ''), field='services_provided'),
                contract_start=_parse_date(request.form.get('contract_start')),
                avv_exists=request.form.get('avv_signed') == 'on',
                avv_signed_at=_parse_date(request.form.get('avv_date')),
                has_iso27001=request.form.get('iso27001_certified') == 'on',
                notes=trunc_text(request.form.get('notes', ''), field='notes'),
            )
            db.session.add(supplier)
            db.session.commit()
            flash(f'Lieferant "{supplier.name}" hinzugefügt.', 'success')
            return redirect(url_for('nis2.supply_chain_detail', supplier_id=supplier.id))

        return render_template('nis2/supply_chain/add_supplier.html',
                               categories=SUPPLIER_CATEGORIES)

    # ── Import via CSV ────────────────────────────────────────────
    @bp.route('/supply-chain/import', methods=['POST'])
    @login_required
    @require_plan("professional")
    @limiter.limit('10 per hour')  # CSV import is heavy — strict limit
    def supply_chain_import():
        file = request.files.get('csv_file')
        if not file or not file.filename.endswith('.csv'):
            flash('Bitte eine CSV-Datei hochladen.', 'error')
            return redirect(url_for('nis2.supply_chain_dashboard'))

        # Size check BEFORE reading into memory — prevents heap-DoS via
        # oversized upload (Python equivalent of buffer-overflow via file I/O)
        from app.input_guard import check_file_size
        if not check_file_size(file, abort_on_exceed=False):
            flash('CSV-Datei zu groß (max. 1 MB).', 'error')
            return redirect(url_for('nis2.supply_chain_dashboard'))

        content = file.read().decode('utf-8-sig')
        reader = csv.DictReader(io.StringIO(content))
        imported = 0
        errors = []

        from app.input_guard import trunc, trunc_text
        for row_num, row in enumerate(reader, start=2):
            name = trunc(row.get('name', ''), 300, field='csv_name')
            if not name:
                errors.append(f'Zeile {row_num}: Name fehlt')
                continue
            supplier = Supplier(
                user_id=current_user.id,
                company_name=name,
                category=trunc(row.get('category', 'other'), 50),
                criticality=trunc(row.get('criticality', 'medium'), 20),
                country=trunc(row.get('country', ''), 100),
                vat_id=trunc(row.get('vat_number', ''), 30),
                contact_email=trunc(row.get('contact_email', ''), 120),
                services_provided=trunc_text(row.get('services_provided', '')),
                avv_exists=row.get('avv_signed', '').lower() in ('ja', 'yes', '1', 'true'),
                has_iso27001=row.get('iso27001_certified', '').lower() in ('ja', 'yes', '1', 'true'),
            )
            db.session.add(supplier)
            imported += 1

        db.session.commit()
        flash(f'{imported} Lieferant(en) importiert.{" Fehler: " + "; ".join(errors) if errors else ""}',
              'success' if not errors else 'warning')
        return redirect(url_for('nis2.supply_chain_dashboard'))

    # ── Supplier detail ───────────────────────────────────────────
    @bp.route('/supply-chain/<int:supplier_id>')
    @login_required
    @require_plan("professional")
    def supply_chain_detail(supplier_id: int):
        supplier = Supplier.query.get_or_404(supplier_id)
        if supplier.user_id != current_user.id:
            abort(403)
        assessments = SupplierAssessment.query.filter_by(supplier_id=supplier_id)\
            .order_by(SupplierAssessment.assessed_at.desc()).all()
        return render_template('nis2/supply_chain/supplier_detail.html',
                               supplier=supplier,
                               assessments=assessments,
                               categories=SUPPLIER_CATEGORIES)

    # ── Update supplier ───────────────────────────────────────────
    @bp.route('/supply-chain/<int:supplier_id>/update', methods=['POST'])
    @login_required
    @require_plan("professional")
    def supply_chain_update(supplier_id: int):
        supplier = Supplier.query.get_or_404(supplier_id)
        if supplier.user_id != current_user.id:
            abort(403)

        from app.input_guard import trunc, trunc_text
        supplier.company_name      = trunc(request.form.get('name', supplier.company_name), 300, field='company_name')
        supplier.category          = trunc(request.form.get('category', supplier.category), 50, field='category')
        supplier.criticality       = trunc(request.form.get('criticality', supplier.criticality), 20, field='criticality')
        supplier.country           = trunc(request.form.get('country', supplier.country), 100, field='country')
        supplier.vat_id            = trunc(request.form.get('vat_number', supplier.vat_id), 30, field='vat_id')
        supplier.contact_email     = trunc(request.form.get('contact_email', supplier.contact_email), 120, field='contact_email')
        supplier.services_provided = trunc_text(request.form.get('services_provided', supplier.services_provided or ''), field='services_provided')
        supplier.avv_exists        = request.form.get('avv_signed') == 'on'
        supplier.avv_signed_at     = _parse_date(request.form.get('avv_date'))
        supplier.avv_review_due    = _parse_date(request.form.get('avv_expiry'))
        supplier.has_iso27001      = request.form.get('iso27001_certified') == 'on'
        supplier.notes             = trunc_text(request.form.get('notes', supplier.notes or ''), field='notes')
        supplier.updated_at = datetime.now(UTC)
        db.session.commit()
        flash('Lieferant aktualisiert.', 'success')
        return redirect(url_for('nis2.supply_chain_detail', supplier_id=supplier_id))

    # ── Quick verification via VIES + Sanctions ───────────────────
    @bp.route('/supply-chain/<int:supplier_id>/verify', methods=['POST'])
    @login_required
    @require_plan("professional")
    def supply_chain_verify(supplier_id: int):
        supplier = Supplier.query.get_or_404(supplier_id)
        if supplier.user_id != current_user.id:
            abort(403)

        results = {}

        # VAT verification via existing VIES service
        if supplier.vat_id:
            try:
                from services.vat_lookup import VatLookupService
                vat_svc = VatLookupService()
                vat_result = vat_svc.lookup(supplier.vat_id)
                results['vat'] = _normalize_vat_result(vat_result)
            except Exception as exc:
                results['vat'] = {'status': 'error', 'error': str(exc)}

        # Sanctions screening via existing service
        try:
            from services.sanctions import SanctionsService
            sanctions = SanctionsService()
            if hasattr(sanctions, 'check_sanctions'):
                sanctions_result = sanctions.check_sanctions(supplier.company_name)
            else:
                sanctions_result = sanctions.check(supplier.company_name, supplier.country or '')
            results['sanctions'] = _normalize_sanctions_result(sanctions_result)
        except Exception as exc:
            results['sanctions'] = {'status': 'error', 'error': str(exc)}

        # Compute new risk score based on results
        risk_score = _compute_risk_score(supplier, results)
        supplier.risk_score = risk_score
        supplier.last_verification_at = datetime.now(UTC)
        supplier.verification_results_json = json.dumps(results, ensure_ascii=False, default=str)
        db.session.commit()

        return jsonify({
            'risk_score': risk_score,
            'risk_color': supplier.risk_color,
            'results': results,
        })

    # ── Add assessment ────────────────────────────────────────────
    @bp.route('/supply-chain/<int:supplier_id>/assess', methods=['POST'])
    @login_required
    @require_plan("professional")
    def supply_chain_assess(supplier_id: int):
        supplier = Supplier.query.get_or_404(supplier_id)
        if supplier.user_id != current_user.id:
            abort(403)

        score = int(request.form.get('score', 50))
        assessment = SupplierAssessment(
            supplier_id=supplier_id,
            risk_score=score,
            notes=request.form.get('notes', ''),
            assessed_by=current_user.id,
            assessed_at=datetime.now(UTC),
        )
        supplier.risk_score = score
        supplier.last_assessment_at = datetime.now(UTC)
        db.session.add(assessment)
        db.session.commit()
        flash('Bewertung gespeichert.', 'success')
        return redirect(url_for('nis2.supply_chain_detail', supplier_id=supplier_id))

    # ── Delete supplier ───────────────────────────────────────────
    @bp.route('/supply-chain/<int:supplier_id>/delete', methods=['POST'])
    @login_required
    @require_plan("professional")
    def supply_chain_delete(supplier_id: int):
        supplier = Supplier.query.get_or_404(supplier_id)
        if supplier.user_id != current_user.id:
            abort(403)
        SupplierAssessment.query.filter_by(supplier_id=supplier_id).delete()
        db.session.delete(supplier)
        db.session.commit()
        flash('Lieferant gelöscht.', 'success')
        return redirect(url_for('nis2.supply_chain_dashboard'))

    # ── CSV template download ─────────────────────────────────────
    @bp.route('/supply-chain/csv-template')
    @login_required
    @require_plan("professional")
    def supply_chain_csv_template():
        from flask import Response
        headers = [
            'name', 'category', 'criticality', 'country', 'vat_number',
            'contact_email', 'services_provided', 'avv_signed', 'iso27001_certified',
        ]
        example = [
            'Muster IT GmbH', 'it_service', 'high', 'DE', 'DE123456789',
            'kontakt@muster.de', 'Cloud-Hosting, Software-Entwicklung', 'ja', 'nein',
        ]
        output = '\n'.join([','.join(headers), ','.join(example)])
        return Response(
            output,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=lieferanten_import_vorlage.csv'},
        )


def _parse_date(value: str):
    if not value:
        return None
    for fmt in ('%Y-%m-%d', '%d.%m.%Y'):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except (ValueError, AttributeError):
            continue
    return None


def _normalize_vat_result(raw) -> dict:
    """Normalize VAT service responses from dict or object stubs."""
    if isinstance(raw, dict):
        return raw

    valid = getattr(raw, 'valid', None)
    company = getattr(raw, 'company_name', None)
    address = getattr(raw, 'address', None)
    error = getattr(raw, 'error', None)

    if valid is True:
        status = 'valid'
    elif valid is False:
        status = 'invalid'
    elif error:
        status = 'error'
    else:
        status = 'unknown'

    return {
        'status': status,
        'prefill': {
            'counterparty_name': company,
            'counterparty_address': address,
        },
        'messages': [],
        'error': error,
    }


def _normalize_sanctions_result(raw) -> dict:
    """Normalize sanctions service responses from dict or object stubs."""
    if isinstance(raw, dict):
        return raw

    clear = getattr(raw, 'clear', None)
    hits = getattr(raw, 'hits', None) or []
    error = getattr(raw, 'error', None)

    if clear is True:
        status = 'clear'
    elif clear is False:
        status = 'hit'
    elif error:
        status = 'error'
    else:
        status = 'unknown'

    return {
        'status': status,
        'sanctions_found': hits,
        'error': error,
    }


def _compute_risk_score(supplier: Supplier, results: dict) -> int:
    """Simple risk scoring based on verification results."""
    score = 50  # baseline

    # Sanctions hit = high risk
    sanctions = results.get('sanctions', {})
    if sanctions.get('status') == 'hit' or sanctions.get('found', False):
        score = 95
        return score

    # VAT invalid
    vat = results.get('vat', {})
    if vat.get('status') == 'invalid':
        score += 20

    # No AVV
    if not supplier.avv_signed:
        score += 10

    # High criticality
    if supplier.criticality == 'critical':
        score += 10
    elif supplier.criticality == 'high':
        score += 5

    # ISO 27001 certified → lower risk
    if supplier.iso27001_certified:
        score -= 15

    return max(0, min(100, score))
