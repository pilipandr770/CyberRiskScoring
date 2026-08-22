"""Fix blog tables schema: move from public → nis2_compliance

Previous migration (a1b2c3d4e5f6) created blog tables without schema awareness.
This migration drops the wrongly-placed tables from public (if they exist there)
using op.execute() — NOT op.get_bind() which is removed in modern Alembic.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-05-15 18:00:00.000000
"""
import os

from alembic import op
from sqlalchemy import text

revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None

_SCHEMA = os.environ.get('DB_SCHEMA') or None


def upgrade():
    # Only clean up if running with a target schema (no-op locally where DB_SCHEMA is unset)
    if _SCHEMA:
        op.execute(text('DROP TABLE IF EXISTS public.blog_post_tags CASCADE'))
        op.execute(text('DROP TABLE IF EXISTS public.blog_posts CASCADE'))
        op.execute(text('DROP TABLE IF EXISTS public.blog_tags CASCADE'))


def downgrade():
    pass  # nothing to undo — the next migration handles table creation
