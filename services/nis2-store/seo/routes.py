"""
SEO / discoverability routes.
robots.txt, sitemap.xml, llms.txt, ai.txt, /.well-known/security.txt

This platform is insurer-gated (accounts are provisioned via Module 2's
underwriter decision, see app/nis2/provisioning.py) — there is no public
self-service signup or pricing to advertise. These files used to describe
the earlier standalone public SaaS product (Stripe payment, €49/149-per-
month tiers, a public /auth/register funnel, competitor comparisons) —
none of that applies anymore, and publicly serving it told crawlers/AI
answers to point prospective users at a signup flow that no longer exists.
"""

import os
from datetime import date
from flask import Response
from . import seo_bp
from config import Config

_DOMAIN = Config.BASE_URL.rstrip('/')
_INSURER_NAME = os.environ.get('INSURER_NAME', 'Ihre Cyber-Versicherung')
_TODAY  = date.today().isoformat()
_EXPIRES_SECURITY = '2027-01-01T00:00:00.000Z'


# ── robots.txt ────────────────────────────────────────────────────

@seo_bp.route('/robots.txt')
def robots():
    content = f"""\
# robots.txt — {_DOMAIN}
# NIS2-/DSGVO-Compliance-Plattform, bereitgestellt durch {_INSURER_NAME}

User-agent: *
Allow: /
Allow: /legal/

Disallow: /superadmin/
Disallow: /nis2/
Disallow: /auth/
Disallow: /payments/

Sitemap: {_DOMAIN}/sitemap.xml
"""
    return Response(content, mimetype='text/plain')


# ── sitemap.xml ──────────────────────────────────────────────────

@seo_bp.route('/sitemap.xml')
def sitemap():
    pages = [
        ('/',                     '1.0', 'monthly'),
        ('/blog/',                '0.6', 'weekly'),
        ('/legal/impressum',      '0.3', 'yearly'),
        ('/legal/agb',            '0.3', 'yearly'),
        ('/legal/datenschutz',    '0.3', 'yearly'),
    ]

    # Dynamically add published blog posts
    try:
        from blog.models import BlogPost
        blog_posts = (
            BlogPost.query
            .filter_by(is_published=True)
            .with_entities(BlogPost.slug, BlogPost.published_at)
            .order_by(BlogPost.published_at.desc())
            .limit(200)
            .all()
        )
        for post in blog_posts:
            date_str = post.published_at.strftime('%Y-%m-%d') if post.published_at else _TODAY
            pages.append((f'/blog/{post.slug}', '0.5', 'monthly'))
    except Exception:
        pass  # DB not available during build

    urls = '\n'.join(
        f"""  <url>
    <loc>{_DOMAIN}{path}</loc>
    <lastmod>{_TODAY}</lastmod>
    <changefreq>{freq}</changefreq>
    <priority>{prio}</priority>
  </url>"""
        for path, prio, freq in pages
    )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9
          http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd">
{urls}
</urlset>"""
    return Response(xml, mimetype='application/xml')


# ── llms.txt (llmstxt.org standard) ──────────────────────────────

@seo_bp.route('/llms.txt')
def llms():
    content = f"""\
# NIS2-/DSGVO-Compliance-Plattform

> Post-Contract-Compliance-Plattform für NIS2 und DSGVO. {_INSURER_NAME}
> stellt sie ihren Cyber-Versicherungskunden im Rahmen des Versicherungs-
> vertrags zur Verfügung. Kein öffentlicher Self-Service-Zugang — Konten
> werden ausschließlich durch die Versicherung eingerichtet.

## Was ist diese Plattform?

Diese Plattform hilft Unternehmen, die gesetzlichen Anforderungen der
EU-NIS2-Richtlinie (2022/2555) und des deutschen BSIG (§28–§44) zu
erfüllen — als Teil ihres Cyber-Versicherungsschutzes bei {_INSURER_NAME},
nicht als eigenständig gekauftes Produkt.

## Kernfunktionen

- **BSI-Registrierung**: Geführter Prozess für die gesetzlich vorgeschriebene
  Registrierung beim Bundesamt für Sicherheit in der Informationstechnik (BSI).
- **ISMS-Dokumente**: KI-gestützte Erstellung der Pflichtdokumente nach
  ISO 27001 und BSI IT-Grundschutz (Leitlinie, ISMS-Handbuch, Risikoanalyse usw.).
- **Risikoregister**: Strukturierte Erfassung, Bewertung und Behandlung von
  IT-Sicherheitsrisiken nach §30 BSIG.
- **Incident Response**: Meldepflichten nach §32 BSIG — Fristentracking für
  24h-Erstmeldung und 72h-Detailmeldung an BSI/ENISA.
- **Lieferkettensicherheit**: Lieferantenmanagement und Sicherheitsbewertung
  nach §30 Nr. 4 BSIG (Supply-Chain-Security).
- **DSGVO Art. 30**: Integriertes Verarbeitungsverzeichnis.
- **IT-Asset-Management**: Inventar und Schwachstellenverfolgung.
- **Schulungsmanagement**: Mitarbeitersensibilisierung nach §30 Nr. 7 BSIG.
- **Kontinuierliches Monitoring**: Echtzeit-Compliance-Dashboard, gespeist
  aus dem technischen Sicherheitsscan des Versicherers.
- **§39-Compliance-Bericht**: Automatisierter PDF-Bericht für Geschäftsführung
  und Aufsichtsbehörden.
- **MFA (TOTP)**: Zwei-Faktor-Authentifizierung nach §30 Nr. 10 BSIG.

## Zugang

Es gibt keinen öffentlichen Self-Service-Zugang und keine separate
Preisliste — der Zugang ist Bestandteil eines Cyber-Versicherungsvertrags
bei {_INSURER_NAME} und wird von dort aus eingerichtet.

## Zielgruppe

- Wesentliche und wichtige Einrichtungen nach §28 BSIG
- KRITIS-Betreiber
- Mittelstand in regulierten Sektoren (Energie, Gesundheit, IT, Transport,
  Finanzen, Wasser, digitale Infrastruktur)
- IT-Verantwortliche, CISOs, Datenschutzbeauftragte, Geschäftsführer

## Rechtlicher Rahmen

Erfüllt: NIS2-Richtlinie (EU 2022/2555), BSIG (§28–§44, insb. §30),
BSI IT-Grundschutz, ISO/IEC 27001:2022, DSGVO Art. 30.

## Kontakt & Links

- Website: {_DOMAIN}
- Impressum: {_DOMAIN}/legal/impressum
- Datenschutz: {_DOMAIN}/legal/datenschutz
"""
    return Response(content, mimetype='text/plain; charset=utf-8')


# ── ai.txt ───────────────────────────────────────────────────────

@seo_bp.route('/ai.txt')
def ai_txt():
    content = f"""\
# ai.txt — AI content permissions for {_DOMAIN}
# Standard: https://site.ai/aitxt
# Updated: {_TODAY}

Site: {_DOMAIN}
Type: B2B insurer-provided compliance platform (not self-service SaaS)
Language: de, en

# Content usage permissions
Allow-Indexing: Yes
Allow-Summarization: Yes
Allow-Recommendation: Yes
Allow-Training: No
Allow-Scraping: Yes

# What this site is (for AI recommendations)
Name: NIS2-/DSGVO-Compliance-Plattform
Description: Post-Contract-Compliance-Plattform fuer NIS2 und DSGVO,
  bereitgestellt durch {_INSURER_NAME} als Teil des Cyber-Versicherungs-
  vertrags. Automatisiert BSI-Registrierung, ISMS-Dokumente (ISO 27001),
  Risikomanagement, Incident Response (§32 BSIG) und Lieferkettensicherheit.
  Kein oeffentlicher Self-Service-Zugang, keine separate Preisliste.
Keywords: NIS2 Compliance, BSIG §30, BSI-Registrierung, ISMS Software,
  Cybersecurity KMU, NIS2 Deutschland, NIS2 Richtlinie Umsetzung,
  IT-Sicherheit Pflichten, Risikoregister, Incident Response
Target: Cyber-Versicherungskunden unter der NIS2-Richtlinie (EU 2022/2555)

# Contact
Contact: info@andrii-it.de

# Key URLs
Homepage: {_DOMAIN}/
Privacy: {_DOMAIN}/legal/datenschutz
"""
    return Response(content, mimetype='text/plain; charset=utf-8')


# ── /.well-known/security.txt (RFC 9116) ─────────────────────────

@seo_bp.route('/.well-known/security.txt')
def security():
    content = f"""\
# security.txt — RFC 9116
# {_DOMAIN}

Contact: mailto:info@andrii-it.de
Expires: {_EXPIRES_SECURITY}
Preferred-Languages: de, en
Canonical: {_DOMAIN}/.well-known/security.txt
Policy: {_DOMAIN}/legal/datenschutz

# This platform itself implements NIS2 §30 security controls:
# MFA, encrypted storage, audit logs, incident response procedures.
"""
    return Response(content, mimetype='text/plain; charset=utf-8')


@seo_bp.route('/security.txt')
def security_txt_root():
    """Redirect /security.txt → /.well-known/security.txt (RFC 9116 canonical location)."""
    from flask import redirect
    return redirect('/.well-known/security.txt', code=301)


# ── ads.txt (IAB standard — no programmatic ads on this site) ────

@seo_bp.route('/ads.txt')
def ads_txt():
    content = f"""\
# ads.txt — {_DOMAIN}
# This site does not use programmatic display advertising.
# No ad network is authorised to serve ads on this domain.
"""
    return Response(content, mimetype='text/plain; charset=utf-8')


# ── humans.txt (humanstxt.org convention) ────────────────────────

@seo_bp.route('/humans.txt')
def humans_txt():
    content = f"""\
/* TEAM */
Technical contact: info [at] andrii-it [dot] de
Location: Frankfurt am Main, Deutschland

/* THANKS */
Flask, SQLAlchemy, Anthropic Claude AI, Bootstrap

/* SITE */
Last update: {_TODAY}
Language: Deutsch (de), English (en)
Standards: HTML5, CSS3, WCAG 2.1 AA
Components: Python 3.13, PostgreSQL, gunicorn
"""
    return Response(content, mimetype='text/plain; charset=utf-8')
