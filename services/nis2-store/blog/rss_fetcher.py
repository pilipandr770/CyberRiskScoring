"""
RSS / Atom feed fetcher — no third-party feed library required.
Uses stdlib xml.etree + requests (already in requirements).
"""

import logging
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# ── Feed sources ──────────────────────────────────────────────────────────────
SOURCES = [
    {
        'name': 'The Hacker News',
        'url':  'https://feeds.feedburner.com/TheHackersNews',
        'lang': 'en',
        'format': 'rss',
    },
    {
        'name': 'Bleeping Computer',
        'url':  'https://www.bleepingcomputer.com/feed/',
        'lang': 'en',
        'format': 'rss',
    },
    {
        'name': 'CISA Alerts',
        'url':  'https://www.cisa.gov/uscert/ncas/alerts.xml',
        'lang': 'en',
        'format': 'rss',
    },
    {
        # Heise Security — confirmed working Atom feed (discovered from homepage link tags)
        'name': 'Heise Security',
        'url':  'https://www.heise.de/security/feed.xml',
        'lang': 'de',
        'format': 'atom',
    },
    {
        # BSI WID (Warning and Information Service) — official BSI advisory feed
        # Old bsi.bund.de RSS paths are dead after site redesign; WID is the successor
        'name': 'BSI WID Advisories',
        'url':  'https://wid.cert-bund.de/content/public/securityAdvisory/rss',
        'lang': 'de',
        'format': 'rss',
    },
    {
        'name': 'Krebs on Security',
        'url':  'https://krebsonsecurity.com/feed/',
        'lang': 'en',
        'format': 'rss',
    },
]

_CONTENT_NS = 'http://purl.org/rss/1.0/modules/content/'
_ATOM_NS    = 'http://www.w3.org/2005/Atom'

_HEADERS = {
    'User-Agent': 'NIS2-Blog-Bot/1.0 (https://nis2.store; info@nis2.store)',
}


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_all_sources(max_per_source: int = 5) -> list[dict]:
    """
    Fetch articles from all configured RSS sources.
    Returns a flat list of article dicts sorted by published_at descending.
    """
    all_articles: list[dict] = []
    for source in SOURCES:
        try:
            articles = _fetch_source(source, max_per_source)
            all_articles.extend(articles)
            logger.info('Fetched %d articles from %s', len(articles), source['name'])
        except Exception as exc:
            logger.warning('Failed to fetch %s: %s', source['name'], exc)
    all_articles.sort(key=lambda a: a['published_at'] or datetime.min.replace(tzinfo=UTC),
                      reverse=True)
    return all_articles


def fetch_one_new_article() -> Optional[dict]:
    """
    Return the single most-recent article not yet stored in the blog DB.
    Returns None if nothing new is found.
    """
    from blog.models import BlogPost
    articles = fetch_all_sources(max_per_source=3)
    for art in articles:
        existing = BlogPost.query.filter_by(source_url=art['url']).first()
        if not existing:
            return art
    return None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _fetch_source(source: dict, max_items: int) -> list[dict]:
    resp = requests.get(source['url'], headers=_HEADERS, timeout=15)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)
    tag = root.tag.lower()

    if 'rss' in tag or root.tag == 'rss':
        return _parse_rss(root, source, max_items)
    if 'feed' in tag or _ATOM_NS in root.tag:
        return _parse_atom(root, source, max_items)

    # Try RSS channel as child
    channel = root.find('channel')
    if channel is not None:
        return _parse_rss(root, source, max_items)

    logger.warning('Unknown feed format from %s (root tag: %s)', source['name'], root.tag)
    return []


def _parse_rss(root: ET.Element, source: dict, max_items: int) -> list[dict]:
    channel = root.find('channel') or root
    items = channel.findall('item')[:max_items]
    results = []
    for item in items:
        title   = _text(item, 'title')
        url     = _text(item, 'link') or _text(item, 'guid')
        pub     = _text(item, 'pubDate')
        summary = (
            _text(item, f'{{{_CONTENT_NS}}}encoded')
            or _text(item, 'description')
            or ''
        )
        results.append({
            'title':        title,
            'url':          url,
            'summary':      _strip_html(summary)[:2000],
            'published_at': _parse_date(pub),
            'source_name':  source['name'],
            'source_lang':  source['lang'],
        })
    return [r for r in results if r['title'] and r['url']]


def _parse_atom(root: ET.Element, source: dict, max_items: int) -> list[dict]:
    ns = _ATOM_NS
    entries = root.findall(f'{{{ns}}}entry')[:max_items]
    results = []
    for entry in entries:
        title   = _text(entry, f'{{{ns}}}title')
        link_el = entry.find(f'{{{ns}}}link')
        url     = link_el.get('href') if link_el is not None else None
        updated = _text(entry, f'{{{ns}}}updated') or _text(entry, f'{{{ns}}}published')
        summary = _text(entry, f'{{{ns}}}content') or _text(entry, f'{{{ns}}}summary') or ''
        results.append({
            'title':        title,
            'url':          url,
            'summary':      _strip_html(summary)[:2000],
            'published_at': _parse_date_iso(updated),
            'source_name':  source['name'],
            'source_lang':  source['lang'],
        })
    return [r for r in results if r['title'] and r['url']]


def _text(el: ET.Element, tag: str) -> Optional[str]:
    child = el.find(tag)
    if child is not None and child.text:
        return child.text.strip()
    return None


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.astimezone(UTC)
    except Exception:
        return None


def _parse_date_iso(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return dt.astimezone(UTC)
    except Exception:
        return _parse_date(date_str)


def _strip_html(text: str) -> str:
    """Remove HTML tags from summary text."""
    import re
    return re.sub(r'<[^>]+>', ' ', text).strip()
