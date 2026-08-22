"""
Shared Flask extensions — single source of truth.
Import `db`, `login_manager`, `mail`, `csrf` from here everywhere.
"""

import os

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_wtf import CSRFProtect
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()
csrf = CSRFProtect()
migrate = Migrate()

# Rate-limit storage. With multiple gunicorn workers 'memory://' is per-worker
# (limits are not shared and reset on restart). Set RATELIMIT_STORAGE_URI to a
# shared backend in production, e.g. redis://<host>:6379 (Render Redis).
_ratelimit_storage = os.environ.get('RATELIMIT_STORAGE_URI', 'memory://')
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=_ratelimit_storage,
)

login_manager.login_view = 'auth.login'
login_manager.login_message = 'Bitte melden Sie sich an, um fortzufahren.'
login_manager.login_message_category = 'warning'
