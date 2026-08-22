"""
Blog models — BlogPost, BlogTag.

Imported by blog/__init__.py so Flask-Migrate discovers them.
"""

import os
from datetime import UTC, datetime

from app.extensions import db

# Mirror the schema convention used by all other models in this project.
# On Render, DB_SCHEMA=nis2_compliance; locally it is unset → public schema.
SCHEMA = os.environ.get('DB_SCHEMA') or None

_fk_prefix = f'{SCHEMA}.' if SCHEMA else ''

# ── Association table ─────────────────────────────────────────────────────────
blog_post_tags = db.Table(
    'blog_post_tags',
    db.Column('post_id', db.Integer,
              db.ForeignKey(f'{_fk_prefix}blog_posts.id', ondelete='CASCADE'),
              primary_key=True),
    db.Column('tag_id', db.Integer,
              db.ForeignKey(f'{_fk_prefix}blog_tags.id', ondelete='CASCADE'),
              primary_key=True),
    **(({'schema': SCHEMA}) if SCHEMA else {}),
)


class BlogTag(db.Model):
    __tablename__ = 'blog_tags'
    __table_args__ = ({'schema': SCHEMA} if SCHEMA else {})

    id   = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60),  unique=True, nullable=False)
    slug = db.Column(db.String(80),  unique=True, nullable=False)

    posts = db.relationship(
        'BlogPost',
        secondary=blog_post_tags,
        back_populates='tags',
        lazy='select',
    )

    def __repr__(self):
        return f'<BlogTag {self.slug}>'


class BlogPost(db.Model):
    __tablename__ = 'blog_posts'
    __table_args__ = ({'schema': SCHEMA} if SCHEMA else {})

    id               = db.Column(db.Integer, primary_key=True)
    slug             = db.Column(db.String(220), unique=True, nullable=False, index=True)
    title            = db.Column(db.String(300), nullable=False)
    seo_title        = db.Column(db.String(70))
    seo_description  = db.Column(db.String(165))

    content_md       = db.Column(db.Text, nullable=False, default='')
    content_html     = db.Column(db.Text)                   # rendered from content_md

    # 'news' = translated from RSS | 'evergreen' = AI-generated NIS2 article
    category         = db.Column(db.String(20), default='evergreen', nullable=False)

    # News articles only
    source_url       = db.Column(db.String(500))
    source_name      = db.Column(db.String(120))

    # Status
    is_published     = db.Column(db.Boolean, default=False, nullable=False, index=True)
    published_at     = db.Column(db.DateTime(timezone=True), index=True)
    created_at       = db.Column(db.DateTime(timezone=True),
                                 default=lambda: datetime.now(UTC), nullable=False)

    reading_time_min = db.Column(db.Integer, default=5)

    tags = db.relationship(
        'BlogTag',
        secondary=blog_post_tags,
        back_populates='posts',
        lazy='joined',
    )

    # ── helpers ───────────────────────────────────────────────────────────────
    @property
    def is_news(self) -> bool:
        return self.category == 'news'

    @property
    def display_date(self) -> str:
        dt = self.published_at or self.created_at
        if dt:
            return dt.strftime('%d.%m.%Y')
        return ''

    def __repr__(self):
        return f'<BlogPost {self.slug!r} published={self.is_published}>'
