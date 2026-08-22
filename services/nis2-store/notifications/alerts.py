"""
Notifications — email alert helpers.

Used by incident_response routes to send BSI submission confirmation emails.
Wraps Flask-Mail for consistency with the rest of the application.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def send_email(
    subject: str,
    recipient: str,
    text_body: str,
    html_body: Optional[str] = None,
) -> bool:
    """
    Send an email via Flask-Mail.
    Must be called inside an active Flask application context.
    Returns True on success, False on failure.
    """
    try:
        from flask import current_app
        from flask_mail import Message
        from app.extensions import mail

        if not current_app.config.get('MAIL_USERNAME'):
            logger.warning('send_email: MAIL_USERNAME not configured — skipping')
            return False

        msg = Message(
            subject=subject,
            recipients=[recipient],
            body=text_body,
            html=html_body,
        )
        mail.send(msg)
        logger.info('Email sent to %s: %s', recipient, subject)
        return True

    except Exception as exc:
        logger.error('send_email failed to %s: %s', recipient, exc)
        return False
