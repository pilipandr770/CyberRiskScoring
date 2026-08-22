"""
Sanctions Screening Service — stub for NIS2 standalone app.
Returns a minimal result so supply chain routes don't crash.
Extend with real sanctions API (e.g. opensanctions.org) if needed.
"""


class SanctionsResult:
    def __init__(self, clear=None, hits=None, error=None):
        self.clear = clear
        self.hits = hits or []
        self.error = error


class SanctionsService:
    def check(self, company_name: str, country: str = '') -> SanctionsResult:
        """
        Stub implementation — returns unknown result.
        Replace with real sanctions API call as needed.
        """
        return SanctionsResult(clear=None, error='Sanktionsprüfung nicht konfiguriert')
