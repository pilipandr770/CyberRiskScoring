"""
User model for the NIS2 Compliance Platform.
Standalone — no dependency on external CRM/VAT modules.
"""

import os
import secrets
from datetime import UTC, datetime, timedelta

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db

SCHEMA = os.environ.get('DB_SCHEMA') or None
_sp = f'{SCHEMA}.' if SCHEMA else ''


class User(UserMixin, db.Model):
    """User with authentication and subscription plan."""

    __tablename__ = 'users'
    __table_args__ = ({'schema': SCHEMA} if SCHEMA else {})

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Profile
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    company_name = db.Column(db.String(200))
    phone = db.Column(db.String(50))
    country = db.Column(db.String(2), default='DE')

    # Business qualification (EU VIES). vat_verified=True only when VIES
    # confirmed the number at registration; unverified means VIES was
    # unreachable but the format was accepted.
    vat_id = db.Column(db.String(20))
    vat_verified = db.Column(db.Boolean, default=False, nullable=False)

    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    is_email_confirmed = db.Column(db.Boolean, default=False)
    email_confirmation_token = db.Column(db.String(100), unique=True)

    # Subscription: 'trial' | 'basic' | 'professional' | 'enterprise'
    subscription_plan = db.Column(db.String(20), default='trial')
    trial_ends_at = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))

    # Password reset
    password_reset_token = db.Column(db.String(100), unique=True)
    password_reset_expires = db.Column(db.DateTime)

    # TOTP / MFA (§30 Nr. 10 BSIG)
    totp_secret = db.Column(db.String(64))
    totp_enabled = db.Column(db.Boolean, default=False, nullable=False)
    totp_backup_codes_json = db.Column(db.Text)  # JSON list of unused backup codes

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    last_login = db.Column(db.DateTime)

    # Anti-abuse forensics — client IP captured at registration (IPv4/IPv6).
    registration_ip = db.Column(db.String(45), index=True)

    def __repr__(self):
        return f'<User {self.email}>'

    # ── Password ──────────────────────────────────────────────────────────

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # ── TOTP / MFA ────────────────────────────────────────────────────────

    def generate_totp_secret(self) -> str:
        import pyotp
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self) -> str:
        import pyotp
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name='NIS2 Compliance Platform',
        )

    def verify_totp(self, code: str) -> bool:
        import pyotp
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(code, valid_window=1)

    def generate_backup_codes(self) -> list:
        codes = [secrets.token_hex(4).upper() for _ in range(8)]
        self.totp_backup_codes_json = __import__('json').dumps(codes)
        return codes

    def use_backup_code(self, code: str) -> bool:
        import json
        if not self.totp_backup_codes_json:
            return False
        codes = json.loads(self.totp_backup_codes_json)
        code_upper = code.strip().upper()
        if code_upper in codes:
            codes.remove(code_upper)
            self.totp_backup_codes_json = json.dumps(codes)
            return True
        return False

    # ── Email confirmation ────────────────────────────────────────────────

    def generate_confirmation_token(self) -> str:
        self.email_confirmation_token = secrets.token_urlsafe(32)
        return self.email_confirmation_token

    def confirm_email(self):
        self.is_email_confirmed = True
        self.email_confirmation_token = None

    # ── Password reset ────────────────────────────────────────────────────

    def generate_reset_token(self) -> str:
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_expires = datetime.now(UTC) + timedelta(hours=2)
        return self.password_reset_token

    def is_reset_token_valid(self, token: str) -> bool:
        if not (self.password_reset_token == token and self.password_reset_expires):
            return False
        exp = self.password_reset_expires
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        return datetime.now(UTC) < exp

    # ── Subscription helpers ──────────────────────────────────────────────

    @property
    def is_trial_active(self) -> bool:
        if self.subscription_plan != 'trial':
            return False
        if not self.trial_ends_at:
            return False
        ends_at = self.trial_ends_at
        if ends_at.tzinfo is None:
            ends_at = ends_at.replace(tzinfo=UTC)
        return datetime.now(UTC) < ends_at

    @property
    def has_access(self) -> bool:
        """Full NIS2 access — was tier-gated (trial/basic/professional/
        enterprise via Stripe), now just requires an active account. Access
        itself is insurer-gated at account-creation time (see
        app/nis2/provisioning.py) — there's nothing left to tier here, same
        reasoning as require_plan() in services/security_helpers.py."""
        return self.is_active

    @property
    def display_name(self) -> str:
        if self.first_name:
            return f'{self.first_name} {self.last_name or ""}'.strip()
        return self.company_name or self.email.split('@')[0]

    @property
    def plan_label(self) -> str:
        # No more tiers (Stripe removed) — access is all-or-nothing via the
        # insurer. is_admin is the one distinction still worth naming.
        return 'Administrator' if self.is_admin else 'Im Versicherungsschutz enthalten'
