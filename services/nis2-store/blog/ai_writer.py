"""
AI Writer — uses Claude API to:
  1. Translate & adapt English/German RSS articles to German NIS2-focused blog posts
  2. Generate full evergreen articles from topic definitions
"""

import logging
import os
from datetime import date, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

_MODEL = 'claude-sonnet-4-6'

_SYSTEM_PROMPT = (
    'Du bist ein erfahrener deutscher Cybersicherheits-Journalist und NIS2-Experte. '
    'Du schreibst professionelle, praxisnahe Blogartikel auf Deutsch für '
    'IT-Verantwortliche und Geschäftsführer in deutschen Unternehmen. '
    'Deine Artikel sind:\n'
    '- Sachlich korrekt mit aktuellen Referenzen (BSI, BSIG, DSGVO, ENISA)\n'
    '- Praxisorientiert mit konkreten Handlungsempfehlungen\n'
    '- SEO-optimiert mit natürlicher Verwendung der Zielkeywords\n'
    '- Im Markdown-Format mit klarer Struktur (H2/H3, Aufzählungen, Tabellen)\n'
    '- Mindestens 800 Wörter, idealerweise 1200–1800 Wörter\n\n'
    'Schließe jeden Artikel mit einem Call-to-Action-Absatz ab, der auf '
    'NIS2-Compliance-Software hinweist (ohne direkte Werbung, als nützlicher Tipp).'
)


def translate_news_article(raw_article: dict) -> Optional[dict]:
    """
    Translate and adapt a raw RSS article (English or German) into a
    German NIS2-focused blog post.

    Input:  raw_article = {title, url, summary, published_at, source_name, source_lang}
    Output: {title, content_md, seo_title, seo_description, tags} or None on error.
    """
    import anthropic

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        logger.error('ANTHROPIC_API_KEY not set — cannot generate blog article')
        return None

    client = anthropic.Anthropic(api_key=api_key)
    today = date.today().strftime('%d.%m.%Y')
    lang_note = (
        'Der Text ist bereits auf Deutsch — passe ihn für ein B2B-Publikum an.'
        if raw_article.get('source_lang') == 'de'
        else 'Der Text ist auf Englisch — übersetze und adaptiere ihn vollständig.'
    )

    prompt = f"""
{lang_note}

**Originaltitel:** {raw_article.get('title', 'Unbekannt')}
**Quelle:** {raw_article.get('source_name', 'Extern')}
**Veröffentlicht:** {today}
**Zusammenfassung / Originaltext:**
{raw_article.get('summary', '')[:1500]}

**Aufgabe:**
Erstelle einen vollständigen deutschen Blogartikel für IT-Verantwortliche und Geschäftsführer.
Struktur:
1. Einleitung (Was ist passiert / warum ist das relevant für deutsche Unternehmen?)
2. Technischer Hintergrund (Was steckt dahinter? Einfach erklärt.)
3. Auswirkungen auf Deutschland / NIS2-Relevanz (Pflichten, Meldewege, BSI)
4. Praktische Schutzmaßnahmen (mindestens 5 konkrete Tipps)
5. Fazit + Call-to-Action

**Gib am Ende in JSON-Format zurück (nach dem Artikel, in einem separaten Block):**
```json
{{
  "suggested_title": "Deutscher SEO-optimierter Titel (max. 65 Zeichen)",
  "seo_description": "Meta-Beschreibung (max. 155 Zeichen)",
  "tags": ["Tag1", "Tag2", "Tag3", "Tag4"]
}}
```
""".strip()

    try:
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=4096,
            system=[{'type': 'text', 'text': _SYSTEM_PROMPT,
                      'cache_control': {'type': 'ephemeral'}}],
            messages=[{'role': 'user', 'content': prompt}],
        )
        full_text = msg.content[0].text if msg.content else ''
        return _parse_ai_response(full_text, raw_article.get('title', ''))
    except Exception as exc:
        logger.error('AI translation failed: %s', exc)
        return None


def generate_evergreen_article(topic: dict) -> Optional[dict]:
    """
    Generate a full evergreen article from a topic definition.

    Input:  topic = {title, category_slug, tags, keywords, nis2_ref, outline}
    Output: {title, content_md, seo_title, seo_description, tags} or None on error.
    """
    import anthropic

    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if not api_key:
        logger.error('ANTHROPIC_API_KEY not set')
        return None

    client = anthropic.Anthropic(api_key=api_key)
    today = date.today().strftime('%d.%m.%Y')
    next_year = (date.today() + timedelta(days=365)).strftime('%d.%m.%Y')

    prompt = f"""
Schreibe einen vollständigen, SEO-optimierten Blogartikel auf Deutsch.

**Titel:** {topic['title']}
**Ziel-Keywords:** {topic['keywords']}
**NIS2-Referenz:** {topic.get('nis2_ref', '§30 BSIG')}
**Gliederungshinweise:** {topic.get('outline', '')}
**Datum:** {today}

**Anforderungen:**
- Mindestens 1200 Wörter, idealerweise 1500–1800 Wörter
- H2 und H3 Überschriften für klare Struktur
- Mindestens eine Tabelle oder Checkliste
- Konkrete Handlungsempfehlungen (nummerierte Liste)
- Korrekte BSIG/NIS2-Paragraphen-Referenzen
- Letzter Abschnitt: "Fazit" mit kurzen nächsten Schritten
- Call-to-Action am Ende (z.B. ISMS-Dokumente erstellen, Betroffenheit prüfen)
- Keine Platzhalter — vollständiger, publizierbarer Text

**Gib am Ende in JSON-Format zurück (nach dem Artikel, in einem separaten ```json Block):**
```json
{{
  "suggested_title": "SEO-Titel (max. 65 Zeichen, enthält Ziel-Keyword)",
  "seo_description": "Meta-Beschreibung (max. 155 Zeichen, enthält Ziel-Keyword)",
  "tags": ["Tag1", "Tag2", "Tag3", "Tag4", "Tag5"]
}}
```
""".strip()

    try:
        msg = client.messages.create(
            model=_MODEL,
            max_tokens=6000,
            system=[{'type': 'text', 'text': _SYSTEM_PROMPT,
                      'cache_control': {'type': 'ephemeral'}}],
            messages=[{'role': 'user', 'content': prompt}],
        )
        full_text = msg.content[0].text if msg.content else ''
        result = _parse_ai_response(full_text, topic['title'])
        if result:
            result['tags'] = result.get('tags') or topic.get('tags', [])
        return result
    except Exception as exc:
        logger.error('AI evergreen generation failed for "%s": %s', topic['title'], exc)
        return None


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_ai_response(full_text: str, fallback_title: str) -> Optional[dict]:
    """
    Split AI response into (article_markdown, metadata_json).
    The AI places metadata in a ```json block at the end.
    """
    import json, re

    if not full_text:
        return None

    # Extract trailing ```json ... ``` block
    meta: dict = {}
    json_pattern = re.search(r'```json\s*(\{.*?\})\s*```', full_text, re.DOTALL)
    if json_pattern:
        try:
            meta = json.loads(json_pattern.group(1))
        except Exception:
            pass
        # Remove the JSON block from the article body
        content_md = full_text[:json_pattern.start()].strip()
    else:
        content_md = full_text.strip()

    title = meta.get('suggested_title') or fallback_title
    seo_description = meta.get('seo_description', '')
    tags = meta.get('tags', [])

    # Build SEO title: keep ≤65 chars
    seo_title = title[:65] if title else fallback_title[:65]

    return {
        'title':           title,
        'seo_title':       seo_title,
        'seo_description': seo_description[:165],
        'content_md':      content_md,
        'tags':            [str(t) for t in tags if t][:6],
    }
