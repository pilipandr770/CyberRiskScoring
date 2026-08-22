"""
Blog scheduler — APScheduler background jobs:

  08:30 daily  → fetch 1 new RSS article → translate → publish
  15:00 daily  → generate + publish 1 evergreen article from queue
"""

import logging
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


def init_blog_scheduler(app) -> BackgroundScheduler:
    """
    Start blog scheduler.  Returns the running BackgroundScheduler instance.
    Attach it to app (e.g. app.blog_scheduler = ...) to prevent GC.
    """
    scheduler = BackgroundScheduler(daemon=True)

    scheduler.add_job(
        _publish_news_job,
        trigger=CronTrigger(hour=8, minute=30),
        args=[app],
        id='blog_news_publish',
        name='Blog: fetch & publish news article',
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        _publish_evergreen_job,
        trigger=CronTrigger(hour=15, minute=0),
        args=[app],
        id='blog_evergreen_publish',
        name='Blog: generate & publish evergreen article',
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.start()
    logger.info('Blog scheduler started (news 08:30, evergreen 15:00)')
    return scheduler


# ── Job implementations ───────────────────────────────────────────────────────

def _publish_news_job(app) -> None:
    """Fetch the most recent unprocessed RSS article, translate it, publish it."""
    with app.app_context():
        try:
            from blog.rss_fetcher import fetch_one_new_article
            from blog.ai_writer import translate_news_article
            from blog.models import BlogPost, BlogTag
            from blog.utils import slugify, make_unique_slug, render_markdown, estimate_reading_time
            from app.extensions import db

            raw = fetch_one_new_article()
            if not raw:
                logger.info('Blog news job: no new articles found in RSS feeds')
                return

            logger.info('Blog news job: processing "%s" from %s',
                        raw['title'], raw['source_name'])

            result = translate_news_article(raw)
            if not result:
                logger.warning('Blog news job: AI translation returned nothing')
                return

            base_slug = slugify(result['title'])
            slug = make_unique_slug(base_slug, BlogPost)

            post = BlogPost(
                slug=slug,
                title=result['title'],
                seo_title=result.get('seo_title', result['title'][:65]),
                seo_description=result.get('seo_description', ''),
                content_md=result['content_md'],
                content_html=render_markdown(result['content_md']),
                category='news',
                source_url=raw['url'],
                source_name=raw['source_name'],
                is_published=True,
                published_at=datetime.now(UTC),
                reading_time_min=estimate_reading_time(result['content_md']),
            )

            # Attach tags
            for tag_name in result.get('tags', []):
                post.tags.append(_get_or_create_tag(tag_name, db))

            db.session.add(post)
            db.session.commit()
            logger.info('Blog news job: published "%s" (slug=%s)', post.title, post.slug)

        except Exception:
            logger.exception('Blog news job: unexpected error')


def _publish_evergreen_job(app) -> None:
    """Pick next unpublished evergreen topic, generate article, publish."""
    with app.app_context():
        try:
            from blog.evergreen_topics import EVERGREEN_TOPICS
            from blog.ai_writer import generate_evergreen_article
            from blog.models import BlogPost, BlogTag
            from blog.utils import slugify, make_unique_slug, render_markdown, estimate_reading_time
            from app.extensions import db

            # Find first topic whose title doesn't appear in existing posts
            published_titles = {p.title for p in BlogPost.query.with_entities(BlogPost.title).all()}
            pending = [t for t in EVERGREEN_TOPICS if t['title'] not in published_titles]

            if not pending:
                logger.info('Blog evergreen job: all %d topics already published',
                            len(EVERGREEN_TOPICS))
                return

            topic = pending[0]
            logger.info('Blog evergreen job: generating "%s"', topic['title'])

            result = generate_evergreen_article(topic)
            if not result:
                logger.warning('Blog evergreen job: AI returned nothing for "%s"', topic['title'])
                return

            base_slug = slugify(result['title'])
            slug = make_unique_slug(base_slug, BlogPost)

            # Use topic tags if AI didn't return enough
            tag_names = result.get('tags') or topic.get('tags', [])

            post = BlogPost(
                slug=slug,
                title=result['title'],
                seo_title=result.get('seo_title', result['title'][:65]),
                seo_description=result.get('seo_description', ''),
                content_md=result['content_md'],
                content_html=render_markdown(result['content_md']),
                category='evergreen',
                is_published=True,
                published_at=datetime.now(UTC),
                reading_time_min=estimate_reading_time(result['content_md']),
            )

            for tag_name in tag_names:
                post.tags.append(_get_or_create_tag(tag_name, db))

            db.session.add(post)
            db.session.commit()
            logger.info('Blog evergreen job: published "%s" (slug=%s)', post.title, post.slug)
            logger.info('Blog evergreen job: %d topics remaining', len(pending) - 1)

        except Exception:
            logger.exception('Blog evergreen job: unexpected error')


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_or_create_tag(name: str, db) -> 'BlogTag':
    from blog.models import BlogTag
    from blog.utils import slugify
    name = name.strip()[:60]
    slug = slugify(name)[:80]
    tag = BlogTag.query.filter_by(slug=slug).first()
    if not tag:
        tag = BlogTag(name=name, slug=slug)
        db.session.add(tag)
    return tag


# ── Manual trigger helpers (for CLI / admin) ──────────────────────────────────

def trigger_news_now(app) -> None:
    """Manually trigger a news article publication (e.g., from Flask CLI)."""
    _publish_news_job(app)


def trigger_evergreen_now(app) -> None:
    """Manually trigger an evergreen article publication."""
    _publish_evergreen_job(app)
