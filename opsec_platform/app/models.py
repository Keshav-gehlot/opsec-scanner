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
    Column, String, Boolean, DateTime, ForeignKey, Text, Integer
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
