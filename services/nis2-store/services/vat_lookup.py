"""
VAT Lookup Service — EU VIES validation.

Validates a VAT/USt-IdNr against the official EU VIES REST API
(https://ec.europa.eu/taxation_customs/vies). Free, no API key.

Notes:
- VIES only covers EU member states.
- Some states (notably Germany) return valid=True but no name/address for
  data-protection reasons — company_name will then be empty.
- VIES has occasional downtime; callers should treat `valid is None` (error)
  as "could not verify" rather than "invalid".
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_VIES_URL = 'https://ec.europa.eu/taxation_customs/vies/rest-api/ms/{cc}/vat/{num}'
_EU_COUNTRIES = frozenset({
    'AT', 'BE', 'BG', 'CY', 'CZ', 'DE', 'DK', 'EE', 'EL', 'ES', 'FI', 'FR',
    'HR', 'HU', 'IE', 'IT', 'LT', 'LU', 'LV', 'MT', 'NL', 'PL', 'PT', 'RO',
    'SE', 'SI', 'SK', 'XI',  # XI = Northern Ireland
})


class VatLookupResult:
    def __init__(self, valid=None, company_name=None, address=None, error=None):
        self.valid = valid            # True / False / None (could not verify)
        self.company_name = company_name
        self.address = address
        self.error = error


def _normalize(vat_number: str, country_code: str = '') -> tuple[str, str]:
    """Return (country_code, number) uppercased and stripped of spaces/dots."""
    raw = re.sub(r'[\s.\-]', '', (vat_number or '')).upper()
    cc = (country_code or '').strip().upper()
    if not cc and len(raw) >= 2 and raw[:2].isalpha():
        cc, raw = raw[:2], raw[2:]
    elif raw[:2] == cc:
        raw = raw[2:]
    return cc, raw


class VatLookupService:
    def lookup(self, vat_number: str, country_code: str = '') -> VatLookupResult:
        import requests

        cc, num = _normalize(vat_number, country_code)
        if not cc or not num:
            return VatLookupResult(valid=False, error='Ungültiges USt-IdNr-Format.')
        if cc not in _EU_COUNTRIES:
            return VatLookupResult(
                valid=None,
                error=f'Land {cc} wird von VIES nicht unterstützt (nur EU).',
            )

        try:
            resp = requests.get(
                _VIES_URL.format(cc=cc, num=num),
                timeout=6,
                headers={'Accept': 'application/json'},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:
            logger.warning('VIES lookup failed for %s%s: %s', cc, num, exc)
            return VatLookupResult(valid=None, error='VAT-Prüfdienst (VIES) nicht erreichbar.')

        # REST API returns key "valid" (older docs used "isValid").
        valid = data.get('valid', data.get('isValid'))
        name = (data.get('name') or '').strip()
        if name in ('---', '', '-'):
            name = None  # e.g. Germany does not disclose the name
        address = (data.get('address') or '').strip() or None
        return VatLookupResult(valid=bool(valid), company_name=name, address=address)
