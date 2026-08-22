"""
NIS2 Compliance Platform — Application Factory
"""

import os
import logging
from datetime import UTC, datetime, timedelta

from flask import Flask, render_template
from sqlalchemy import text

from config import config
from app.extensions import db, login_manager, mail, csrf, migrate, limiter

logger = logging.getLogger(__name__)


def create_app(config_name: str = None) -> Flask:
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__, template_folder='../templates', static_folder='../static')

    # Behind Render's proxy: trust one hop of X-Forwarded-For/Proto so that
    # request.remote_addr is the real client IP (needed for correct rate
    # limiting and registration-IP logging), not the proxy address.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Load config
    cfg_cls = config[config_name]
    cfg_obj = cfg_cls() if isinstance(cfg_cls, type) else cfg_cls
    app.config.from_object(cfg_obj)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)

    # User loader
    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Ensure DB schema exists (PostgreSQL)
    _ensure_schema(app)

    # ── Blueprints ────────────────────────────────────────────────────────
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from payments.routes import payments_bp
    app.register_blueprint(payments_bp, url_prefix='/payments')

    from app.nis2 import nis2_bp
    app.register_blueprint(nis2_bp, url_prefix='/nis2')

    from app.nis2.provisioning import provisioning_bp
    app.register_blueprint(provisioning_bp, url_prefix='/api')

    from legal.routes import legal_bp
    app.register_blueprint(legal_bp, url_prefix='/legal')

    from app.admin import admin_bp
    app.register_blueprint(admin_bp, url_prefix='/superadmin')

    from seo import seo_bp
    app.register_blueprint(seo_bp)

    from blog import blog_bp
    from blog.models import BlogPost, BlogTag  # noqa — ensure Flask-Migrate discovers models
    app.register_blueprint(blog_bp, url_prefix='/blog')

    # Ensure blog tables exist — idempotent raw-SQL fallback so the app
    # never crashes even if Alembic migrations haven't run yet.
    _ensure_blog_tables(app)

    # ── NIS2 monitoring scheduler ─────────────────────────────────────────
    if not app.config.get('DISABLE_NIS2_SCHEDULER', False):
        try:
            from app.nis2.continuous_monitoring.scheduler import init_nis2_monitoring_scheduler
            app.nis2_scheduler = init_nis2_monitoring_scheduler(app)
        except Exception as exc:
            logger.warning('Monitoring scheduler not started: %s', exc)

    # ── Blog scheduler ────────────────────────────────────────────────────
    if not app.config.get('DISABLE_BLOG_SCHEDULER', False):
        try:
            from blog.scheduler import init_blog_scheduler
            app.blog_scheduler = init_blog_scheduler(app)
        except Exception as exc:
            logger.warning('Blog scheduler not started: %s', exc)

    # ── Security headers ──────────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
        # same-origin-allow-popups preserves OAuth popup flows
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
        # CSP: unsafe-inline kept for Jinja templates; CDN + Google Fonts whitelisted.
        # Stripe entries removed — no payment integration anymore (access is
        # insurer-provisioned, see app/nis2/provisioning.py).
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
            "https://challenges.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
            "https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com "
            "https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-src https://challenges.cloudflare.com;"
        )
        if not app.debug:
            response.headers['Strict-Transport-Security'] = (
                'max-age=63072000; includeSubDomains'
            )
        return response

    # ── Landing / root route ──────────────────────────────────────────────
    @app.route('/')
    def index():
        return render_template('landing.html')

    # ── Context processors ────────────────────────────────────────────────
    @app.context_processor
    def inject_globals():
        return {
            'now': datetime.now(UTC),
            'app_name': 'NIS2 Compliance Platform',
            # Placeholder single-tenant branding — becomes a per-insurer DB
            # field once multi-tenancy is built (mirrors risk-scanner's
            # INSURER_NAME). One env var is enough while there's one insurer.
            'insurer_name': os.environ.get('INSURER_NAME', 'Ihre Cyber-Versicherung'),
        }

    # ── CLI commands ──────────────────────────────────────────────────────
    import click

    @app.cli.command('blog-news')
    def blog_news():
        """Manually trigger: fetch RSS article → translate → publish."""
        from blog.scheduler import trigger_news_now
        trigger_news_now(app)
        click.echo('Blog news job done.')

    @app.cli.command('blog-evergreen')
    def blog_evergreen():
        """Manually trigger: generate + publish next evergreen article."""
        from blog.scheduler import trigger_evergreen_now
        trigger_evergreen_now(app)
        click.echo('Blog evergreen job done.')

    @app.cli.command('create-admin')
    @click.option('--email', prompt='Admin email')
    @click.option('--password', prompt='Admin password', hide_input=True, confirmation_prompt=True)
    @click.option('--plan', default='enterprise')
    @click.option('--first-name', default='Admin')
    @click.option('--last-name', default='User')
    def create_admin(email, password, plan, first_name, last_name):
        """Create or promote a user to super-admin."""
        user = User.query.filter_by(email=email).first()
        if user:
            user.is_admin = True
            user.is_active = True
            user.subscription_plan = plan
            user.set_password(password)
            db.session.commit()
            click.echo(f'Updated existing user {email} → admin=True, plan={plan}')
        else:
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                subscription_plan=plan,
                is_admin=True,
                is_active=True,
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            click.echo(f'Created admin user {email} (plan={plan})')

    # ── Error pages ───────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template('errors/405.html'), 405

    @app.errorhandler(413)
    def request_too_large(e):
        # Triggered by MAX_CONTENT_LENGTH — the Flask equivalent of a
        # "buffer overrun detected" error: request body exceeded allowed size.
        return render_template('errors/413.html'), 413

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    return app


def _ensure_schema(app: Flask):
    schema = os.environ.get('DB_SCHEMA')
    db_uri = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if not schema or not db_uri.startswith('postgresql://'):
        return
    try:
        with app.app_context():
            with db.engine.connect() as conn:
                conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
                conn.commit()
    except Exception as exc:
        logger.error('Failed to ensure schema %s: %s', schema, exc)


def _ensure_blog_tables(app: Flask):
    """
    Create blog tables via raw SQL if they don't exist.

    This is a reliable startup-time fallback that runs regardless of whether
    Alembic migrations completed successfully.  All statements use
    CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS so repeated
    calls are completely harmless.
    """
    schema = os.environ.get('DB_SCHEMA') or None
    pfx    = f'{schema}.' if schema else ''

    statements = [
        # ── blog_tags ─────────────────────────────────────────────────────
        f"""CREATE TABLE IF NOT EXISTS {pfx}blog_tags (
            id   SERIAL      PRIMARY KEY,
            name VARCHAR(60) NOT NULL,
            slug VARCHAR(80) NOT NULL,
            CONSTRAINT uq_blog_tags_name UNIQUE (name),
            CONSTRAINT uq_blog_tags_slug UNIQUE (slug)
        )""",

        # ── blog_posts ────────────────────────────────────────────────────
        f"""CREATE TABLE IF NOT EXISTS {pfx}blog_posts (
            id               SERIAL        PRIMARY KEY,
            slug             VARCHAR(220)  NOT NULL,
            title            VARCHAR(300)  NOT NULL,
            seo_title        VARCHAR(70),
            seo_description  VARCHAR(165),
            content_md       TEXT          NOT NULL DEFAULT '',
            content_html     TEXT,
            category         VARCHAR(20)   NOT NULL DEFAULT 'evergreen',
            source_url       VARCHAR(500),
            source_name      VARCHAR(120),
            is_published     BOOLEAN       NOT NULL DEFAULT false,
            published_at     TIMESTAMPTZ,
            created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            reading_time_min INTEGER                DEFAULT 5,
            CONSTRAINT uq_blog_posts_slug UNIQUE (slug)
        )""",

        f"CREATE INDEX IF NOT EXISTS ix_blog_posts_slug         ON {pfx}blog_posts (slug)",
        f"CREATE INDEX IF NOT EXISTS ix_blog_posts_is_published ON {pfx}blog_posts (is_published)",
        f"CREATE INDEX IF NOT EXISTS ix_blog_posts_published_at ON {pfx}blog_posts (published_at)",

        # ── blog_post_tags (M2M) ──────────────────────────────────────────
        f"""CREATE TABLE IF NOT EXISTS {pfx}blog_post_tags (
            post_id INTEGER NOT NULL
                REFERENCES {pfx}blog_posts (id) ON DELETE CASCADE,
            tag_id  INTEGER NOT NULL
                REFERENCES {pfx}blog_tags  (id) ON DELETE CASCADE,
            PRIMARY KEY (post_id, tag_id)
        )""",
    ]

    try:
        with app.app_context():
            with db.engine.connect() as conn:
                for stmt in statements:
                    conn.execute(text(stmt))
                conn.commit()
        logger.info('Blog tables verified / created (schema=%s)', schema or 'public')
    except Exception as exc:
        logger.error('_ensure_blog_tables failed: %s', exc)
