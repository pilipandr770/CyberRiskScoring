"""Add users.vat_id / vat_verified (business qualification) — idempotent

Adds nullable vat_id + vat_verified columns to the users table.
Uses raw ADD COLUMN IF NOT EXISTS so it is safe regardless of prior state.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-07-01 12:30:00.000000
"""
import os

from alembic import op
from sqlalchemy import text

revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None

_SCHEMA = os.environ.get('DB_SCHEMA') or None
_PFX = f'{_SCHEMA}.' if _SCHEMA else ''


def upgrade():
    op.execute(text(
        f'ALTER TABLE {_PFX}users ADD COLUMN IF NOT EXISTS vat_id VARCHAR(20)'
    ))
    op.execute(text(
        f'ALTER TABLE {_PFX}users ADD COLUMN IF NOT EXISTS vat_verified '
        f'BOOLEAN NOT NULL DEFAULT false'
    ))


def downgrade():
    op.execute(text(f'ALTER TABLE {_PFX}users DROP COLUMN IF EXISTS vat_verified'))
    op.execute(text(f'ALTER TABLE {_PFX}users DROP COLUMN IF EXISTS vat_id'))
