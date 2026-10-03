"""
Database models.

Org           — a company/team that provisions local username+password
                accounts for its members ("login and password provided
                by organization").
User          — a person who can log in, either via a local
                org-provisioned password or via SSO (Google/GitHub/
                Microsoft/Apple). auth_provider + provider_user_id
                identify which; both are null for a pure local account.
Session       — one row per issued login session. The JWT handed to the
                browser is stateless and self-verifying, but it carries
                this row's id as its `jti` claim, so a session can
                actually be revoked (logout, admin action) instead of
                just "hope the client throws the cookie away" — a bare
                stateless JWT can't be revoked before it expires.
ActivityLog   — every login attempt (success or failure), logout, and
                (optionally) scan-run event, so "activity on this
                platform can be tracked" is a real, queryable log, not
                just a claim.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Boolean, DateTime, Float, ForeignKey, Text, Integer, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Org(Base):
    __tablename__ = "orgs"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False, unique=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    users = relationship("User", back_populates="org")


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    org_id = Column(String, ForeignKey("orgs.id"), nullable=True)
    email = Column(String, nullable=False, unique=True, index=True)
    display_name = Column(String, nullable=True)

    # Null for SSO-only accounts — there's no local password to check.
    hashed_password = Column(String, nullable=True)

    # "local" | "google" | "github" | "microsoft" | "apple". A user
    # could in principle have both a local password AND have linked an
    # SSO provider, but v1 keeps this simple: one primary auth method
    # per account, matching how most org-provisioned + SSO setups
    # actually behave in practice.
    auth_provider = Column(String, nullable=False, default="local")
    provider_user_id = Column(String, nullable=True, index=True)  # the SSO provider's own user id

    # Closes the gap the previous pass flagged explicitly in the README:
    # "/auth/register has no admin gate yet." True only for the user who
    # bootstraps a brand-new org (the first account created for it) —
    # only an org admin can add further users to that org afterward.
    is_org_admin = Column(Boolean, nullable=False, default=False)

    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)

    org = relationship("Org", back_populates="users")
    sessions = relationship("Session", back_populates="user")

    @property
    def org_name(self) -> str | None:
        return self.org.name if self.org is not None else None
    identities = relationship("UserIdentity", back_populates="user")


class UserIdentity(Base):
    """One external sign-in identity (provider + the provider's stable
    subject id, e.g. Google's `sub`) linked to a User.

    A user can hold a local password and any number of linked identities
    at the same time; signing in with one never disables another. The
    provider subject — not the email address — is the lookup key, as
    providers recommend.
    """

    __tablename__ = "user_identities"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_user_identities_provider_subject"),
    )

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String, nullable=False)
    provider_user_id = Column(String, nullable=False)
    email_at_link = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)

    user = relationship("User", back_populates="identities")


class Session(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True, default=_uuid)  # this is the JWT's `jti`
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, nullable=False, default=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

    user = relationship("User", back_populates="sessions")


class ActivityLog(Base):
    __tablename__ = "activity_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    # Nullable: a failed login before we've matched an email to a real
    # user is still worth logging (brute-force visibility), but there's
    # no user_id to attach it to yet.
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    event_type = Column(String, nullable=False)  # see activity.py EventType for the fixed set
    timestamp = Column(DateTime(timezone=True), default=_now, nullable=False)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    detail = Column(Text, nullable=True)  # short human-readable detail, e.g. "3 CRITICAL findings"


class ApiToken(Base):
    """Personal access token for non-browser clients (the CLI's
    --report-activity / --upload-findings). Only a SHA-256 hash of the
    token is stored; the plaintext is shown once at creation. Tokens are
    accepted only by the scan-ingest and activity-report APIs, never by
    account, session, or organization management routes."""

    __tablename__ = "api_tokens"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    prefix = Column(String, nullable=False)  # first characters, safe to display
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)


class IdentityProfile(Base):
    """The web equivalent of the CLI's target_profile.yaml: the identity
    anchors a user's scans are correlated against. Stored as JSON text so
    the shape can follow opsec_scanner.config.TargetProfile."""

    __tablename__ = "identity_profiles"

    user_id = Column(String, ForeignKey("users.id"), primary_key=True)
    data = Column(Text, nullable=False, default="{}")
    updated_at = Column(DateTime(timezone=True), default=_now, nullable=False)


class Scan(Base):
    """One scan run: a CLI result uploaded to the platform, or a scan the
    platform executed itself (uploaded media files / public git repo).

    Raw secret values are never persisted. Findings keep a redacted
    preview plus a keyed fingerprint so scans of the same target can be
    diffed (new / still open / resolved) without storing the secret."""

    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    org_id = Column(String, ForeignKey("orgs.id"), nullable=True, index=True)
    source = Column(String, nullable=False)          # cli_upload | json_import | media_upload | git_url
    target_label = Column(String, nullable=False)
    status = Column(String, nullable=False, default="queued")  # queued | running | completed | failed
    error = Column(Text, nullable=True)
    stats = Column(Text, nullable=True)              # JSON object
    total_findings = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    max_risk_score = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), default=_now, nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String, nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    risk_label = Column(String, nullable=False)
    rule_id = Column(String, nullable=False)
    category = Column(String, nullable=False)
    preview = Column(String, nullable=False)          # redacted, never the full value
    matched_length = Column(Integer, nullable=False, default=0)
    base_severity = Column(Float, nullable=True)
    entropy_score = Column(Float, nullable=True)
    identity_confidence = Column(Float, nullable=True)
    identity_reason = Column(Text, nullable=True)
    exposure_level = Column(String, nullable=True)
    source_type = Column(String, nullable=True)
    origin = Column(Text, nullable=True)
    context = Column(Text, nullable=True)
    occurrence_count = Column(Integer, nullable=False, default=1)

    scan = relationship("Scan", back_populates="findings")
