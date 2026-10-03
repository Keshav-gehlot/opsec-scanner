"""
Linked sign-in identities (Google/GitHub/Microsoft/Apple) for a User.

Lookup is by (provider, provider subject id), never by email. Linking an
SSO identity to an account that already exists requires the account owner
to prove control with their password: the OAuth callback parks the
verified identity in the signed OAuth session (PENDING_LINK_KEY) and
/auth/login completes the link after a successful password check.
"""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.models import User, UserIdentity

PENDING_LINK_KEY = "pending_sso_link"


def find_user_by_identity(db: DBSession, provider: str, subject: str) -> User | None:
    row = (
        db.query(UserIdentity)
        .filter(UserIdentity.provider == provider, UserIdentity.provider_user_id == subject)
        .first()
    )
    if row is not None:
        return db.query(User).filter(User.id == row.user_id).first()
    # Legacy rows written before user_identities existed (normally moved by
    # database.backfill_user_identities at startup).
    return (
        db.query(User)
        .filter(User.auth_provider == provider, User.provider_user_id == subject)
        .first()
    )


def _oauth_session(request: Request) -> dict | None:
    # SessionMiddleware is only installed when SSO is enabled.
    return request.session if "session" in request.scope else None


def complete_pending_link(db: DBSession, request: Request, user: User) -> str | None:
    """After a successful password login, link a parked SSO identity.

    Only links when the identity's provider-verified email is this user's
    email. Always clears the pending entry. Returns the linked provider
    name, or None when nothing was linked.
    """
    session = _oauth_session(request)
    if session is None:
        return None
    pending = session.pop(PENDING_LINK_KEY, None)
    if not isinstance(pending, dict):
        return None
    provider = pending.get("provider")
    subject = pending.get("provider_user_id")
    if not provider or not subject or pending.get("email") != (user.email or "").lower():
        return None
    if find_user_by_identity(db, provider, subject) is not None:
        return None  # already linked (to this or another account) — never re-point it
    db.add(UserIdentity(user_id=user.id, provider=provider, provider_user_id=subject, email_at_link=user.email))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    return provider
