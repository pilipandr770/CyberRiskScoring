"""Add users.registration_ip (anti-abuse forensics) — idempotent

Adds a nullable registration_ip column + index to the users table.
Uses raw ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS so it is safe
to run regardless of prior migration state.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-07-01 12:00:00.000000
"""
import os

from alembic import op
from sqlalchemy import text

revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None

_SCHEMA = os.environ.get('DB_SCHEMA') or None
_PFX = f'{_SCHEMA}.' if _SCHEMA else ''


def upgrade():
    op.execute(text(
        f'ALTER TABLE {_PFX}users ADD COLUMN IF NOT EXISTS registration_ip VARCHAR(45)'
    ))
    op.execute(text(
        f'CREATE INDEX IF NOT EXISTS ix_users_registration_ip '
        f'ON {_PFX}users (registration_ip)'
    ))


def downgrade():
    op.execute(text(f'DROP INDEX IF EXISTS {_PFX}ix_users_registration_ip'))
    op.execute(text(f'ALTER TABLE {_PFX}users DROP COLUMN IF EXISTS registration_ip'))
