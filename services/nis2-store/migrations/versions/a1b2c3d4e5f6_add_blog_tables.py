"""Add blog tables in correct schema (blog_posts, blog_tags, blog_post_tags)

Revision ID: a1b2c3d4e5f6
Revises: 256ba9082e98
Create Date: 2026-05-15 12:00:00.000000

"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '256ba9082e98'
branch_labels = None
depends_on = None

# Mirror the schema convention of the rest of the project.
# On Render: DB_SCHEMA=nis2_compliance → tables go in that schema.
# Locally (no DB_SCHEMA set) → tables go in public.
_SCHEMA = os.environ.get('DB_SCHEMA') or None


def _tbl(name: str) -> str:
    """Return schema-qualified table name string for ForeignKeyConstraints."""
    return f'{_SCHEMA}.{name}' if _SCHEMA else name


def upgrade():
    conn = op.get_bind()

    # ── Drop tables from public schema if they were accidentally created there ──
    # (happens when previous migration run lacked DB_SCHEMA env var)
    if _SCHEMA:
        conn.execute(text('DROP TABLE IF EXISTS public.blog_post_tags CASCADE'))
        conn.execute(text('DROP TABLE IF EXISTS public.blog_posts CASCADE'))
        conn.execute(text('DROP TABLE IF EXISTS public.blog_tags CASCADE'))

    # app/__init__.py's _ensure_blog_tables() creates these same tables via a
    # raw-SQL "CREATE TABLE IF NOT EXISTS" fallback on every app boot,
    # including the boot triggered by `flask db upgrade` itself — on a truly
    # fresh database that fallback wins the race and this migration's plain
    # op.create_table() then fails with DuplicateTable. Skip whatever the
    # fallback already created; only create what's actually still missing.
    inspector = sa.inspect(conn)
    existing = set(inspector.get_table_names(schema=_SCHEMA))
    if 'blog_tags' in existing and 'blog_posts' in existing and 'blog_post_tags' in existing:
        return

    # ── blog_tags ─────────────────────────────────────────────────────────────
    op.create_table(
        'blog_tags',
        sa.Column('id',   sa.Integer(), nullable=False),
        sa.Column('name', sa.String(60), nullable=False),
        sa.Column('slug', sa.String(80), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('slug'),
        schema=_SCHEMA,
    )

    # ── blog_posts ────────────────────────────────────────────────────────────
    op.create_table(
        'blog_posts',
        sa.Column('id',               sa.Integer(),               nullable=False),
        sa.Column('slug',             sa.String(220),             nullable=False),
        sa.Column('title',            sa.String(300),             nullable=False),
        sa.Column('seo_title',        sa.String(70),              nullable=True),
        sa.Column('seo_description',  sa.String(165),             nullable=True),
        sa.Column('content_md',       sa.Text(),                  nullable=False,
                  server_default=''),
        sa.Column('content_html',     sa.Text(),                  nullable=True),
        sa.Column('category',         sa.String(20),              nullable=False,
                  server_default='evergreen'),
        sa.Column('source_url',       sa.String(500),             nullable=True),
        sa.Column('source_name',      sa.String(120),             nullable=True),
        sa.Column('is_published',     sa.Boolean(),               nullable=False,
                  server_default='false'),
        sa.Column('published_at',     sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at',       sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text('NOW()')),
        sa.Column('reading_time_min', sa.Integer(),               nullable=True,
                  server_default='5'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug'),
        schema=_SCHEMA,
    )
    op.create_index('ix_blog_posts_slug',         'blog_posts', ['slug'],
                    unique=True,  schema=_SCHEMA)
    op.create_index('ix_blog_posts_is_published', 'blog_posts', ['is_published'],
                    unique=False, schema=_SCHEMA)
    op.create_index('ix_blog_posts_published_at', 'blog_posts', ['published_at'],
                    unique=False, schema=_SCHEMA)

    # ── blog_post_tags (M2M) ──────────────────────────────────────────────────
    op.create_table(
        'blog_post_tags',
        sa.Column('post_id', sa.Integer(), nullable=False),
        sa.Column('tag_id',  sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ['post_id'], [_tbl('blog_posts') + '.id'], ondelete='CASCADE'
        ),
        sa.ForeignKeyConstraint(
            ['tag_id'], [_tbl('blog_tags') + '.id'], ondelete='CASCADE'
        ),
        sa.PrimaryKeyConstraint('post_id', 'tag_id'),
        schema=_SCHEMA,
    )


def downgrade():
    op.drop_table('blog_post_tags', schema=_SCHEMA)
    op.drop_index('ix_blog_posts_published_at', table_name='blog_posts', schema=_SCHEMA)
    op.drop_index('ix_blog_posts_is_published', table_name='blog_posts', schema=_SCHEMA)
    op.drop_index('ix_blog_posts_slug',         table_name='blog_posts', schema=_SCHEMA)
    op.drop_table('blog_posts', schema=_SCHEMA)
    op.drop_table('blog_tags',  schema=_SCHEMA)
