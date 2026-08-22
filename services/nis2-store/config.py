"""
NIS2 Compliance Platform — Configuration
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # ── Database ──────────────────────────────────────────────────────────
    _db_url = os.environ.get('DATABASE_URL') or \
              os.environ.get('LOCAL_DATABASE_URL') or \
              'postgresql://postgres:postgres@localhost:5432/nis2_dev'

    # Render.com uses postgres:// — fix it
    if _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)

    SQLALCHEMY_DATABASE_URI = _db_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    _engine_opts = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
        'pool_size': 5,
        'max_overflow': 10,
    }
    if _db_url.startswith('postgresql://'):
        _connect_args = {
            'options': f'-csearch_path={os.environ.get("DB_SCHEMA", "public")}',
            'connect_timeout': 10,
        }
        if 'render.com' in _db_url or os.environ.get('RENDER'):
            _connect_args['sslmode'] = 'require'
        _engine_opts['connect_args'] = _connect_args
    SQLALCHEMY_ENGINE_OPTIONS = _engine_opts

    # ── Mail / SMTP ───────────────────────────────────────────────────────
    MAIL_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('SMTP_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False') == 'True'
    MAIL_USERNAME = os.environ.get('SMTP_USERNAME')
    MAIL_PASSWORD = os.environ.get('SMTP_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get(
        'MAIL_DEFAULT_SENDER', 'noreply@nis2-compliance.de'
    )

    # ── AI (LLM provider) ─────────────────────────────────────────────────
    # LLM_PROVIDER selects the backend: 'anthropic' (default) or 'mistral'
    # (Mistral AI — EU data residency, for GDPR/NIS2-sensitive customers).
    LLM_PROVIDER = os.environ.get('LLM_PROVIDER', 'anthropic')
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
    MISTRAL_API_KEY = os.environ.get('MISTRAL_API_KEY')

    # ── NIS2 Microservice — now risk-scanner (Module 1), not a paid tier ───
    NIS2_MICROSERVICE_URL = os.environ.get('NIS2_MICROSERVICE_URL')
    NIS2_MICROSERVICE_API_KEY = os.environ.get('NIS2_MICROSERVICE_API_KEY')

    # ── Provisioning — inbound calls from risk-scanner (Module 2) when an
    # underwriter accepts a decision. Access to this platform is insurer-
    # gated: no public self-service signup, no paid tiers.
    M3_PROVISIONING_API_KEY = os.environ.get('M3_PROVISIONING_API_KEY')

    # ── Trial period (days) ───────────────────────────────────────────────
    TRIAL_DAYS = int(os.environ.get('TRIAL_DAYS', 14))

    # ── Site URL ──────────────────────────────────────────────────────────
    BASE_URL = os.environ.get('SITE_BASE_URL', 'https://nis2-compliance.de')

    # ── Input size limits (buffer-overflow / DoS protection) ─────────────
    # Flask aborts with 413 Request Entity Too Large if body exceeds this.
    # 2 MB covers the largest legitimate form (ISMS doc ~500 KB markdown).
    # File uploads go through the same limit — CSV imports are small.
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB

    # Maximum characters accepted for any free-text / Text column field.
    # Enforced at the Python layer (before the DB even sees the data).
    MAX_TEXT_FIELD    = 100_000   # 100 KB — generous for an ISMS document
    MAX_STRING_FIELD  = 1_000     # 1 KB — ample for names, titles, slugs
    MAX_FILE_BYTES    = 1 * 1024 * 1024  # 1 MB — CSV import hard limit


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False

    # Secure session cookies (HTTPS only, no JS access, CSRF protection)
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = timedelta(days=7)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    def __init__(self):
        required = {
            'SECRET_KEY': os.environ.get('SECRET_KEY'),
            'DATABASE_URL': os.environ.get('DATABASE_URL'),
        }
        missing = [k for k, v in required.items()
                   if not v or v == 'dev-secret-key-change-in-production']
        if missing:
            raise RuntimeError(
                f'Production startup blocked. Missing env vars: {", ".join(missing)}'
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    DISABLE_NIS2_SCHEDULER = True
    DISABLE_BLOG_SCHEDULER = True
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig,
}
