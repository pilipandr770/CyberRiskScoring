"""add api_usage_logs

Revision ID: 256ba9082e98
Revises: 8c8fe298cbed
Create Date: 2026-05-13 21:42:56.518257

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '256ba9082e98'
down_revision = '8c8fe298cbed'
branch_labels = None
depends_on = None


def upgrade():
    schema = 'nis2_compliance'
    op.create_table(
        'nis2_api_usage_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('model', sa.String(length=60), nullable=False),
        sa.Column('endpoint', sa.String(length=60), nullable=False),
        sa.Column('input_tokens', sa.Integer(), nullable=True),
        sa.Column('output_tokens', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], [f'{schema}.users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        schema=schema,
    )
    with op.batch_alter_table('nis2_api_usage_logs', schema=schema) as batch_op:
        batch_op.create_index('ix_nis2_api_usage_logs_created_at', ['created_at'], unique=False)
        batch_op.create_index('ix_nis2_api_usage_logs_user_id', ['user_id'], unique=False)


def downgrade():
    schema = 'nis2_compliance'
    with op.batch_alter_table('nis2_api_usage_logs', schema=schema) as batch_op:
        batch_op.drop_index('ix_nis2_api_usage_logs_user_id')
        batch_op.drop_index('ix_nis2_api_usage_logs_created_at')
    op.drop_table('nis2_api_usage_logs', schema=schema)
