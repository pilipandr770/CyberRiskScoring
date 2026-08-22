"""
Blog public routes:
  GET /blog/               → paginated article list
  GET /blog/<slug>         → single article
  GET /blog/tag/<tag-slug> → articles by tag
  GET /blog/feed.xml       → RSS 2.0 feed
"""

import logging
from datetime import UTC, datetime

from flask import abort, render_template, request, make_response

from blog import blog_bp
from blog.models import BlogPost, BlogTag, blog_post_tags
from app.extensions import db

logger = logging.getLogger(__name__)
_PER_PAGE = 12


@blog_bp.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', '')

    try:
        query = BlogPost.query.filter_by(is_published=True)
        if category in ('news', 'evergreen'):
            query = query.filter_by(category=category)

        pagination = (
            query
            .order_by(BlogPost.published_at.desc())
            .paginate(page=page, per_page=_PER_PAGE, error_out=False)
        )

        # Tags that have at least one published post — use subquery (.any()) instead of
        # .join() on the relationship to stay compatible with SQLAlchemy 2.x
        popular_tags = (
            BlogTag.query
            .filter(BlogTag.posts.any(BlogPost.is_published == True))
            .order_by(BlogTag.name)
            .limit(30)
            .all()
        )

        recent_posts = (
            BlogPost.query
            .filter_by(is_published=True)
            .order_by(BlogPost.published_at.desc())
            .limit(5)
            .all()
        )

    except Exception:
        logger.exception('Blog index query failed')
        db.session.rollback()
        pagination = None
        popular_tags = []
        recent_posts = []

    return render_template(
        'blog/index.html',
        pagination=pagination,
        posts=pagination.items if pagination else [],
        popular_tags=popular_tags,
        recent_posts=recent_posts,
        active_category=category,
    )


@blog_bp.route('/<slug>')
def article(slug):
    try:
        post = BlogPost.query.filter_by(slug=slug, is_published=True).first_or_404()

        # Related: same tags, exclude self, max 3
        related = []
        if post.tags:
            tag_ids = [t.id for t in post.tags]
            related = (
                BlogPost.query
                .filter(
                    BlogPost.is_published == True,
                    BlogPost.id != post.id,
                    BlogPost.tags.any(BlogTag.id.in_(tag_ids)),
                )
                .order_by(BlogPost.published_at.desc())
                .limit(3)
                .all()
            )
    except Exception:
        logger.exception('Blog article query failed for slug=%s', slug)
        db.session.rollback()
        abort(500)

    return render_template('blog/article.html', post=post, related=related)


@blog_bp.route('/tag/<tag_slug>')
def tag(tag_slug):
    try:
        blog_tag = BlogTag.query.filter_by(slug=tag_slug).first_or_404()
        page = request.args.get('page', 1, type=int)

        # Use BlogPost.query with .any() subquery — avoids lazy='dynamic' requirement
        pagination = (
            BlogPost.query
            .filter(
                BlogPost.is_published == True,
                BlogPost.tags.any(BlogTag.id == blog_tag.id),
            )
            .order_by(BlogPost.published_at.desc())
            .paginate(page=page, per_page=_PER_PAGE, error_out=False)
        )
    except Exception:
        logger.exception('Blog tag query failed for slug=%s', tag_slug)
        db.session.rollback()
        abort(500)

    return render_template(
        'blog/tag.html',
        tag=blog_tag,
        pagination=pagination,
        posts=pagination.items,
    )


@blog_bp.route('/feed.xml')
def feed():
    try:
        posts = (
            BlogPost.query
            .filter_by(is_published=True)
            .order_by(BlogPost.published_at.desc())
            .limit(20)
            .all()
        )
    except Exception:
        logger.exception('Blog feed query failed')
        db.session.rollback()
        posts = []

    now_rfc = _rfc2822(datetime.now(UTC))

    items_xml = ''
    for p in posts:
        pub_date = _rfc2822(p.published_at) if p.published_at else now_rfc
        desc = (p.seo_description or p.title or '')
        items_xml += f"""
  <item>
    <title><![CDATA[{p.title}]]></title>
    <link>https://nis2.store/blog/{p.slug}</link>
    <guid isPermaLink="true">https://nis2.store/blog/{p.slug}</guid>
    <pubDate>{pub_date}</pubDate>
    <description><![CDATA[{desc}]]></description>
    {''.join(f'<category>{t.name}</category>' for t in p.tags)}
  </item>"""

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>NIS2 Compliance Blog — Cybersicherheit &amp; NIS2 für Deutschland</title>
  <link>https://nis2.store/blog/</link>
  <description>Aktuelle Cybersicherheitsnews und NIS2-Ratgeber für deutsche Unternehmen</description>
  <language>de</language>
  <lastBuildDate>{now_rfc}</lastBuildDate>
  <atom:link href="https://nis2.store/blog/feed.xml" rel="self" type="application/rss+xml"/>
{items_xml}
</channel>
</rss>"""

    response = make_response(xml)
    response.headers['Content-Type'] = 'application/rss+xml; charset=utf-8'
    return response


# ── Helpers ───────────────────────────────────────────────────────────────────

def _rfc2822(dt: datetime) -> str:
    from email.utils import format_datetime
    return format_datetime(dt)
