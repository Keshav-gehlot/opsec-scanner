"""baseline schema

The schema as of v0.10.0, when the platform moved from create_all() to
Alembic. Existing databases are stamped at this revision instead of running
it (see opsec_platform.app.database.init_db).

Revision ID: 0001_baseline
Revises: 
Create Date: 2026-11-13 18:35:11.839279
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = '0001_baseline'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('orgs',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('users',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('org_id', sa.String(), nullable=True),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('display_name', sa.String(), nullable=True),
    sa.Column('hashed_password', sa.String(), nullable=True),
    sa.Column('auth_provider', sa.String(), nullable=False),
    sa.Column('provider_user_id', sa.String(), nullable=True),
    sa.Column('is_org_admin', sa.Boolean(), nullable=False),
    sa.Column('is_active', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['orgs.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_users_email'), ['email'], unique=True)
        batch_op.create_index(batch_op.f('ix_users_provider_user_id'), ['provider_user_id'], unique=False)

    op.create_table('activity_log',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.String(), nullable=True),
    sa.Column('event_type', sa.String(), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ip_address', sa.String(), nullable=True),
    sa.Column('user_agent', sa.String(), nullable=True),
    sa.Column('detail', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('api_tokens',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('token_hash', sa.String(), nullable=False),
    sa.Column('prefix', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_api_tokens_token_hash'), ['token_hash'], unique=True)
        batch_op.create_index(batch_op.f('ix_api_tokens_user_id'), ['user_id'], unique=False)

    op.create_table('finding_states',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('target_label', sa.String(), nullable=False),
    sa.Column('fingerprint', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('note', sa.Text(), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'target_label', 'fingerprint', name='uq_finding_state')
    )
    with op.batch_alter_table('finding_states', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_finding_states_user_id'), ['user_id'], unique=False)

    op.create_table('identity_profiles',
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('data', sa.Text(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('user_id')
    )
    op.create_table('integrations',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('kind', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('config_encrypted', sa.Text(), nullable=False),
    sa.Column('config_hint', sa.String(), nullable=True),
    sa.Column('min_severity', sa.String(), nullable=False),
    sa.Column('only_new', sa.Boolean(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_sent_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_status', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('integrations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_integrations_user_id'), ['user_id'], unique=False)

    op.create_table('monitored_targets',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('org_id', sa.String(), nullable=True),
    sa.Column('kind', sa.String(), nullable=False),
    sa.Column('value', sa.String(), nullable=False),
    sa.Column('verification_token', sa.String(), nullable=False),
    sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('verification_method', sa.String(), nullable=True),
    sa.Column('schedule', sa.String(), nullable=False),
    sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_scan_id', sa.String(), nullable=True),
    sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['orgs.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id', 'kind', 'value', name='uq_monitored_target')
    )
    with op.batch_alter_table('monitored_targets', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_monitored_targets_next_run_at'), ['next_run_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_monitored_targets_user_id'), ['user_id'], unique=False)

    op.create_table('scans',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('org_id', sa.String(), nullable=True),
    sa.Column('source', sa.String(), nullable=False),
    sa.Column('target_label', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('stats', sa.Text(), nullable=True),
    sa.Column('total_findings', sa.Integer(), nullable=False),
    sa.Column('critical_count', sa.Integer(), nullable=False),
    sa.Column('high_count', sa.Integer(), nullable=False),
    sa.Column('medium_count', sa.Integer(), nullable=False),
    sa.Column('low_count', sa.Integer(), nullable=False),
    sa.Column('max_risk_score', sa.Float(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['orgs.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scans_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_org_id'), ['org_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_user_id'), ['user_id'], unique=False)

    op.create_table('sessions',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('revoked', sa.Boolean(), nullable=False),
    sa.Column('ip_address', sa.String(), nullable=True),
    sa.Column('user_agent', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user_identities',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('user_id', sa.String(), nullable=False),
    sa.Column('provider', sa.String(), nullable=False),
    sa.Column('provider_user_id', sa.String(), nullable=False),
    sa.Column('email_at_link', sa.String(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider', 'provider_user_id', name='uq_user_identities_provider_subject')
    )
    with op.batch_alter_table('user_identities', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_user_identities_user_id'), ['user_id'], unique=False)

    op.create_table('findings',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('fingerprint', sa.String(), nullable=False),
    sa.Column('risk_score', sa.Float(), nullable=False),
    sa.Column('risk_label', sa.String(), nullable=False),
    sa.Column('rule_id', sa.String(), nullable=False),
    sa.Column('category', sa.String(), nullable=False),
    sa.Column('preview', sa.String(), nullable=False),
    sa.Column('matched_length', sa.Integer(), nullable=False),
    sa.Column('base_severity', sa.Float(), nullable=True),
    sa.Column('entropy_score', sa.Float(), nullable=True),
    sa.Column('identity_confidence', sa.Float(), nullable=True),
    sa.Column('identity_reason', sa.Text(), nullable=True),
    sa.Column('exposure_level', sa.String(), nullable=True),
    sa.Column('source_type', sa.String(), nullable=True),
    sa.Column('origin', sa.Text(), nullable=True),
    sa.Column('context', sa.Text(), nullable=True),
    sa.Column('occurrence_count', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_findings_fingerprint'), ['fingerprint'], unique=False)
        batch_op.create_index(batch_op.f('ix_findings_scan_id'), ['scan_id'], unique=False)



def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_scan_id'))
        batch_op.drop_index(batch_op.f('ix_findings_fingerprint'))

    op.drop_table('findings')
    with op.batch_alter_table('user_identities', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_user_identities_user_id'))

    op.drop_table('user_identities')
    op.drop_table('sessions')
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_scans_user_id'))
        batch_op.drop_index(batch_op.f('ix_scans_org_id'))
        batch_op.drop_index(batch_op.f('ix_scans_created_at'))

    op.drop_table('scans')
    with op.batch_alter_table('monitored_targets', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_monitored_targets_user_id'))
        batch_op.drop_index(batch_op.f('ix_monitored_targets_next_run_at'))

    op.drop_table('monitored_targets')
    with op.batch_alter_table('integrations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_integrations_user_id'))

    op.drop_table('integrations')
    op.drop_table('identity_profiles')
    with op.batch_alter_table('finding_states', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_finding_states_user_id'))

    op.drop_table('finding_states')
    with op.batch_alter_table('api_tokens', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_api_tokens_user_id'))
        batch_op.drop_index(batch_op.f('ix_api_tokens_token_hash'))

    op.drop_table('api_tokens')
    op.drop_table('activity_log')
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_provider_user_id'))
        batch_op.drop_index(batch_op.f('ix_users_email'))

    op.drop_table('users')
    op.drop_table('orgs')
