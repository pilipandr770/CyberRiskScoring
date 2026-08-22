"""
Blog utility functions: slugify, reading-time, Markdown→HTML.
"""

import re
import unicodedata

import markdown
import bleach

# Allowed HTML tags after Markdown rendering
_ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'ul', 'ol', 'li',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'code', 'pre', 'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'a', 'img', 'hr',
]
_ALLOWED_ATTRS = {
    'a':   ['href', 'title', 'rel', 'target'],
    'img': ['src', 'alt', 'title', 'width', 'height'],
    '*':   ['class'],
}

_UMLAUT_MAP = str.maketrans({
    'ä': 'ae', 'ö': 'oe', 'ü': 'ue', 'ß': 'ss',
    'Ä': 'Ae', 'Ö': 'Oe', 'Ü': 'Ue',
})


def slugify(text: str) -> str:
    """Convert a German title to a URL-safe slug."""
    text = text.translate(_UMLAUT_MAP)
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    text = re.sub(r'-{2,}', '-', text)
    return text.strip('-')[:200]


def estimate_reading_time(content: str) -> int:
    """Estimate reading time in minutes (200 wpm)."""
    words = len(content.split())
    return max(1, round(words / 200))


def render_markdown(md_text: str) -> str:
    """Render Markdown to sanitised HTML."""
    if not md_text:
        return ''
    html = markdown.markdown(
        md_text,
        extensions=['tables', 'fenced_code', 'toc', 'nl2br'],
    )
    return bleach.clean(html, tags=_ALLOWED_TAGS, attributes=_ALLOWED_ATTRS, strip=True)


def make_unique_slug(base_slug: str, model_class) -> str:
    """Append a numeric suffix to base_slug until it is unique in the DB."""
    slug = base_slug
    n = 1
    while model_class.query.filter_by(slug=slug).first():
        slug = f'{base_slug}-{n}'
        n += 1
    return slug
