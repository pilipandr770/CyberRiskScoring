"""Create blog tables in correct schema using raw SQL (idempotent)

Uses CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS only.
Works regardless of prior migration state.

Migration chain:
  a1b2c3d4e5f6 (original blog tables — ran without schema, in public)
  → b2c3d4e5f6a7 (drops public.blog_* tables when DB_SCHEMA is set)
  → c3d4e5f6a7b8 (THIS — creates tables in correct schema)

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-05-15 19:00:00.000000
"""
import os

from alembic import op
from sqlalchemy import text

revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None

_SCHEMA = os.environ.get('DB_SCHEMA') or None
_PFX   = f'{_SCHEMA}.' if _SCHEMA else ''


def upgrade():
    # ── Ensure target schema exists ───────────────────────────────────────────
    if _SCHEMA:
        op.execute(text(f'CREATE SCHEMA IF NOT EXISTS {_SCHEMA}'))

    # ── blog_tags ─────────────────────────────────────────────────────────────
    op.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {_PFX}blog_tags (
            id   SERIAL      PRIMARY KEY,
            name VARCHAR(60) NOT NULL,
            slug VARCHAR(80) NOT NULL,
            CONSTRAINT uq_blog_tags_name UNIQUE (name),
            CONSTRAINT uq_blog_tags_slug UNIQUE (slug)
        )
    """))

    # ── blog_posts ────────────────────────────────────────────────────────────
    op.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {_PFX}blog_posts (
            id               SERIAL        PRIMARY KEY,
            slug             VARCHAR(220)  NOT NULL,
            title            VARCHAR(300)  NOT NULL,
            seo_title        VARCHAR(70),
            seo_description  VARCHAR(165),
            content_md       TEXT          NOT NULL DEFAULT '',
            content_html     TEXT,
            category         VARCHAR(20)   NOT NULL DEFAULT 'evergreen',
            source_url       VARCHAR(500),
            source_name      VARCHAR(120),
            is_published     BOOLEAN       NOT NULL DEFAULT false,
            published_at     TIMESTAMPTZ,
            created_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
            reading_time_min INTEGER                DEFAULT 5,
            CONSTRAINT uq_blog_posts_slug UNIQUE (slug)
        )
    """))

    op.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_blog_posts_slug
        ON {_PFX}blog_posts (slug)
    """))
    op.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_blog_posts_is_published
        ON {_PFX}blog_posts (is_published)
    """))
    op.execute(text(f"""
        CREATE INDEX IF NOT EXISTS ix_blog_posts_published_at
        ON {_PFX}blog_posts (published_at)
    """))

    # ── blog_post_tags (M2M) ──────────────────────────────────────────────────
    op.execute(text(f"""
        CREATE TABLE IF NOT EXISTS {_PFX}blog_post_tags (
            post_id INTEGER NOT NULL
                REFERENCES {_PFX}blog_posts (id) ON DELETE CASCADE,
            tag_id  INTEGER NOT NULL
                REFERENCES {_PFX}blog_tags  (id) ON DELETE CASCADE,
            PRIMARY KEY (post_id, tag_id)
        )
    """))


def downgrade():
    op.execute(text(f'DROP TABLE IF EXISTS {_PFX}blog_post_tags CASCADE'))
    op.execute(text(f'DROP TABLE IF EXISTS {_PFX}blog_posts CASCADE'))
    op.execute(text(f'DROP TABLE IF EXISTS {_PFX}blog_tags  CASCADE'))
