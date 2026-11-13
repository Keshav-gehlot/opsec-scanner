"""
Optional first-admin bootstrap from PLATFORM_BOOTSTRAP_ADMIN_EMAIL /
PLATFORM_BOOTSTRAP_ADMIN_PASSWORD.

Previous behaviour created the account once and never touched its password
again, accepted any password (a short dictionary password was in use in
production), and had no way to rotate it: the app has no password-change
endpoint. Rules now:

- HTTPS deployments refuse a weak bootstrap password (< 12 chars, or
  containing the email's local part). If the existing bootstrap account
  still has exactly that weak password, its password login is disabled and
  its sessions revoked, closing the hole even before anyone edits the env.
- A strong password that differs from the stored one rotates it (and revokes
  the account's sessions), so changing the env var is a real rotation.
- Concurrent workers creating the account at once no longer crash startup.
"""

from __future__ import annotations

import logging

from sqlalchemy.exc import IntegrityError

from opsec_platform.app.models import Org, Session as SessionModel, User
from opsec_platform.app.security import hash_password, verify_password

logger = logging.getLogger(__name__)

MIN_BOOTSTRAP_PASSWORD_CHARS = 12
BOOTSTRAP_ORG_NAME = "OPSEC Scanner"


def bootstrap_password_problem(email: str, password: str) -> str | None:
    if len(password) < MIN_BOOTSTRAP_PASSWORD_CHARS:
        return f"must be at least {MIN_BOOTSTRAP_PASSWORD_CHARS} characters"
    local = email.split("@")[0].lower()
    if local and len(local) >= 3 and local in password.lower():
        return "must not contain the email's local part"
    if len(set(password)) < 6:
        return "is too repetitive"
    return None


def _revoke_sessions(db, user: User) -> None:
    db.query(SessionModel).filter(SessionModel.user_id == user.id, SessionModel.revoked.is_(False)) \
        .update({SessionModel.revoked: True}, synchronize_session=False)


def run_bootstrap_admin(session_factory, email: str, password: str, secure: bool) -> str:
    """Returns a short status string (for logs/tests); never raises on policy."""
    email = (email or "").strip().lower()
    if not email or not password:
        return "disabled"

    problem = bootstrap_password_problem(email, password) if secure else None
    db = session_factory()
    try:
        admin = db.query(User).filter(User.email == email).first()

        if problem:
            logger.error("PLATFORM_BOOTSTRAP_ADMIN_PASSWORD %s; bootstrap admin not created/updated.", problem)
            if admin is not None and admin.hashed_password and verify_password(password, admin.hashed_password):
                admin.hashed_password = None
                _revoke_sessions(db, admin)
                db.commit()
                logger.error("Disabled password login for the bootstrap admin: it still used the weak "
                             "bootstrap password. Set a strong PLATFORM_BOOTSTRAP_ADMIN_PASSWORD to restore it.")
                return "weak-locked"
            return "weak-skipped"

        if admin is None:
            org = db.query(Org).filter(Org.name == BOOTSTRAP_ORG_NAME).first()
            if org is None:
                org = Org(name=BOOTSTRAP_ORG_NAME)
                db.add(org)
                db.flush()
            db.add(User(
                org_id=org.id, email=email, display_name="Administrator",
                hashed_password=hash_password(password), auth_provider="local",
                is_org_admin=True, is_active=True,
            ))
            try:
                db.commit()
            except IntegrityError:
                db.rollback()  # another worker created it first
                return "exists"
            return "created"

        changed = "unchanged"
        if not admin.is_org_admin:
            admin.is_org_admin = True
            changed = "promoted"
        if not admin.hashed_password or not verify_password(password, admin.hashed_password):
            admin.hashed_password = hash_password(password)
            _revoke_sessions(db, admin)
            changed = "rotated"
        db.commit()
        return changed
    finally:
        db.close()
