"""
Email policy — business-only registration gate.

NIS2 targets companies (§30 BSIG applies to medium+ entities), so private
freemail and disposable addresses are rejected at registration. This also
blocks the bulk of signup bots, which overwhelmingly use freemail.

`is_business_email(email)` returns (ok, reason). Existing accounts are never
affected — this is only enforced on new registrations.
"""

from __future__ import annotations

# Consumer / free webmail providers (international + DACH). Not exhaustive, but
# covers the overwhelming majority of private and bot registrations.
FREEMAIL_DOMAINS: frozenset[str] = frozenset({
    # Google / Apple / Microsoft
    'gmail.com', 'googlemail.com',
    'icloud.com', 'me.com', 'mac.com',
    'outlook.com', 'outlook.de', 'hotmail.com', 'hotmail.de', 'hotmail.co.uk',
    'hotmail.fr', 'live.com', 'live.de', 'msn.com',
    # Yahoo / AOL
    'yahoo.com', 'yahoo.de', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.it', 'ymail.com',
    'aol.com', 'aol.de',
    # DACH freemail
    'gmx.de', 'gmx.net', 'gmx.com', 'gmx.at', 'gmx.ch',
    'web.de', 't-online.de', 'freenet.de', 'arcor.de', 'online.de',
    'bluewin.ch', 'gmx.li',
    # Privacy mail
    'protonmail.com', 'proton.me', 'pm.me', 'tutanota.com', 'tuta.io',
    # Other large freemail
    'mail.com', 'email.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.ru',
    'inbox.com', 'gmx.us', 'fastmail.com',
    # US ISP freemail seen in the bot wave
    'sbcglobal.net', 'cox.net', 'comcast.net', 'verizon.net', 'att.net',
    'bellsouth.net', 'charter.net', 'earthlink.net',
})

# Common disposable / throwaway providers.
DISPOSABLE_DOMAINS: frozenset[str] = frozenset({
    'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
    'temp-mail.org', 'throwawaymail.com', 'yopmail.com', 'trashmail.com',
    'getnada.com', 'sharklasers.com', 'maildrop.cc', 'dispostable.com',
    'fakeinbox.com', 'mohmal.com', 'mintemail.com', 'emailondeck.com',
})


def _domain(email: str) -> str:
    return email.rsplit('@', 1)[-1].strip().lower() if '@' in email else ''


def is_business_email(email: str) -> tuple[bool, str | None]:
    """Return (ok, reason). reason is a German user-facing message when ok is False."""
    domain = _domain(email)
    if not domain or '.' not in domain:
        return False, 'Bitte geben Sie eine gültige E-Mail-Adresse ein.'
    if domain in DISPOSABLE_DOMAINS:
        return False, 'Wegwerf-E-Mail-Adressen sind nicht zulässig. Bitte verwenden Sie Ihre geschäftliche E-Mail-Adresse.'
    if domain in FREEMAIL_DOMAINS:
        return False, ('Bitte registrieren Sie sich mit Ihrer geschäftlichen E-Mail-Adresse '
                       '(Unternehmensdomain). Private E-Mail-Anbieter werden nicht akzeptiert.')
    return True, None
