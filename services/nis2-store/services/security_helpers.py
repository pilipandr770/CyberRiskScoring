"""
Security helpers — was plan-based feature gating (trial < basic <
professional < enterprise), now a no-op login check. Access to this
platform is insurer-gated (provisioned once, full feature set), not sold
as tiered self-service plans — there's nothing left to rank.

`require_plan(...)` is kept (rather than deleted) so every route that
already decorates with `@require_plan("professional")` etc. keeps working
without touching each call site; the plan-name argument is now ignored.
"""

import functools
from flask import redirect, url_for
from flask_login import current_user


def require_plan(*_required_plans: str):
    """Decorator — requires login only. Plan-name arguments are accepted
    for call-site compatibility but no longer affect access."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('auth.login'))
            return f(*args, **kwargs)
        return wrapper
    return decorator
