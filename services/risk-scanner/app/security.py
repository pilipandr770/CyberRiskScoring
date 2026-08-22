"""CSRF protection and rate-limit key helpers.

Cookie-session auth (this app) is exactly the setup CSRF targets: a logged-in
agent's browser will happily attach the session cookie to a form POST
triggered by an unrelated site. The machine API (routers/api.py) is exempt —
it authenticates via X-API-Key header, not cookies, so cross-site forms can't
forge those calls.
"""

import hmac
import secrets

from fastapi import HTTPException, Request, status

CSRF_SESSION_KEY = "csrf_token"


def get_csrf_token(request: Request) -> str:
    token = request.session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        request.session[CSRF_SESSION_KEY] = token
    return token


def verify_csrf(request: Request, submitted_token: str) -> None:
    expected = request.session.get(CSRF_SESSION_KEY)
    if not expected or not submitted_token or not hmac.compare_digest(expected, submitted_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Formular abgelaufen oder ungültig. Bitte Seite neu laden und erneut versuchen.",
        )


def client_ip(request: Request) -> str:
    """Best-effort real client IP for rate-limiting behind Cloudflare+Traefik.

    Cloudflare sets CF-Connecting-IP authoritatively; fall back to the
    leftmost X-Forwarded-For entry, then the direct peer (local dev, no
    proxy in front).
    """
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
