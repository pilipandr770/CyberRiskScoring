from flask import Blueprint

seo_bp = Blueprint('seo', __name__)

from . import routes  # noqa: E402, F401
