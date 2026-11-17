"""finding AI triage verdict

Adds the optional LLM triage verdict (likely_real / likely_test / unclear)
and a one-line reason to findings. Both stay NULL unless PLATFORM_LLM_TRIAGE
is enabled.

Revision ID: 0002_ai_triage
Revises: 0001_baseline
Create Date: 2026-11-14 10:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0002_ai_triage'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # A pre-Alembic database repaired with create_all() may already have them.
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns('findings')}
    with op.batch_alter_table('findings') as batch:
        if 'ai_verdict' not in existing:
            batch.add_column(sa.Column('ai_verdict', sa.String(), nullable=True))
        if 'ai_reason' not in existing:
            batch.add_column(sa.Column('ai_reason', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch:
        batch.drop_column('ai_reason')
        batch.drop_column('ai_verdict')
