"""
OAuth/SSO routes: /auth/oauth/{provider}/login redirects to the
provider's consent screen; /auth/oauth/{provider}/callback handles the
return trip, finds-or-creates a User, and issues a session — the same
session mechanism as local login (same Session row + JWT shape), so
downstream code never needs to care whether someone logged in with a
password or with Google.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as DBSession

from opsec_platform.app.activity import log_activity, EventType
from opsec_platform.app.config import get_settings
from opsec_platform.app.dependencies import SESSION_COOKIE_NAME
from opsec_platform.app.models import User, Session as SessionModel
from opsec_platform.app.oauth_providers import build_oauth_registry

router = APIRouter(prefix="/auth/oauth", tags=["oauth"])
logger = logging.getLogger(__name__)

SUPPORTED_PROVIDERS = {"google", "github", "microsoft", "apple"}


def _client_meta(request: Request) -> tuple[str, str]:
    return request.client.host if request.client else "unknown", request.headers.get("user-agent", "unknown")


def _require_configured_provider(provider: str):
    if provider not in SUPPORTED_PROVIDERS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown provider '{provider}'.")

    settings = get_settings()
    cfg = settings.oauth_providers()[provider]
    if not cfg.is_configured:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                f"{provider.capitalize()} sign-in is not configured on this server. "
                f"Set {provider.upper()}_CLIENT_ID and {provider.upper()}_CLIENT_SECRET "
                f"— see opsec_platform/README.md for how to register an app with {provider.capitalize()} "
                f"and obtain these values."
            ),
        )
    return settings


@router.get("/{provider}/login")
async def oauth_login(provider: str, request: Request):
    settings = _require_configured_provider(provider)
    oauth = build_oauth_registry(settings)
    client = oauth.create_client(provider)
    redirect_uri = f"{settings.base_url.rstrip('/')}/auth/oauth/{provider}/callback"
    try:
        return await client.authorize_redirect(request, redirect_uri)
    except Exception as e:
        logger.exception("OAuth redirect initialization failed for provider=%s", provider)
        # OIDC providers (google/microsoft/apple) fetch a live discovery
        # document on first use — a network hiccup or provider outage
        # here would otherwise surface as a raw unhandled exception to
        # whoever clicked "sign in with X," rather than a clean error.
        # (GitHub doesn't hit this path — it uses static URLs, no
        # discovery fetch — which is how this gap was found: verifying
        # the redirect worked for GitHub but not for Google surfaced the
        # difference.)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Could not reach {provider.capitalize()} to start sign-in. Try again shortly.",
        ) from e


async def _fetch_provider_identity(provider: str, oauth, request: Request) -> dict:
    """Returns a normalized {provider_user_id, email, display_name} dict
    regardless of which provider it came from — the three providers have
    three different shapes of "who is this," normalized here once so
    the callback route below doesn't need provider-specific branching."""
    client = oauth.create_client(provider)
    token = await client.authorize_access_token(request)

    if provider in ("google", "microsoft", "apple"):
        # All three are OIDC-compliant — identity comes from the verified id_token.
        userinfo = token.get("userinfo") or await client.userinfo(token=token)
        return {
            "provider_user_id": userinfo.get("sub"),
            "email": userinfo.get("email"),
            "email_verified": userinfo.get("email_verified"),
            "display_name": userinfo.get("name") or userinfo.get("email"),
        }
    elif provider == "github":
        # GitHub isn't OIDC — fetch the user profile via REST, and emails
        # separately since a GitHub account's primary email can be
        # private and absent from /user.
        resp = await client.get("user", token=token)
        profile = resp.json()
        emails_resp = await client.get("user/emails", token=token)
        emails = emails_resp.json()
        verified_primary = next((e.get("email") for e in emails if e.get("primary") and e.get("verified")), None)
        verified_any = next((e.get("email") for e in emails if e.get("verified")), None)
        email = verified_primary or verified_any
        return {
            "provider_user_id": str(profile.get("id")),
            "email": email,
            "email_verified": bool(email),
            "display_name": profile.get("name") or profile.get("login"),
        }
    raise ValueError(f"unhandled provider: {provider}")  # unreachable given SUPPORTED_PROVIDERS gate above


@router.api_route("/{provider}/callback", methods=["GET", "POST"])
async def oauth_callback(request: Request):
    provider = request.path_params["provider"]
    settings = _require_configured_provider(provider)
    oauth = build_oauth_registry(settings)

    # Use an explicit DB session for the OAuth callback so GET and POST
    # callbacks share the same transaction lifecycle.
    from opsec_platform.app.dependencies import _SessionLocal, configure_db
    if _SessionLocal is None:
        configure_db()
    db: DBSession = _SessionLocal()

    ip, ua = _client_meta(request)
    try:
        identity = await _fetch_provider_identity(provider, oauth, request)
    except Exception as e:
        log_activity(db, EventType.OAUTH_LOGIN_FAILED, ip_address=ip, user_agent=ua, detail=f"{provider}: {e}")
        db.close()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"{provider.capitalize()} sign-in failed.")

    if not identity.get("provider_user_id"):
        log_activity(db, EventType.OAUTH_LOGIN_FAILED, ip_address=ip, user_agent=ua, detail=f"{provider}: no provider user id returned")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{provider.capitalize()} did not provide a usable account identifier.",
        )

    if not identity.get("email"):
        log_activity(db, EventType.OAUTH_LOGIN_FAILED, ip_address=ip, user_agent=ua, detail=f"{provider}: no email returned")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{provider.capitalize()} did not provide an email address for this account.",
        )

    # Account linking is keyed by email, so only accept an identity whose
    # provider explicitly verified that email address. This applies to
    # every supported SSO provider; otherwise an unverified provider claim
    # could be used to take over a matching local account.
    if identity.get("email_verified") is not True:
        log_activity(db, EventType.OAUTH_LOGIN_FAILED, ip_address=ip, user_agent=ua, detail=f"{provider}: email not verified")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{provider.capitalize()} did not provide a verified email address for this account.",
        )

    try:
        user = (
            db.query(User)
            .filter(User.auth_provider == provider, User.provider_user_id == identity["provider_user_id"])
            .first()
        )
        if user is None:
            # Not linked yet — if an account with this email already
            # exists (e.g. a local account), link this SSO identity to
            # it rather than creating a duplicate account for the same
            # person.
            user = db.query(User).filter(User.email == identity["email"]).first()
            if user is None:
                user = User(
                    email=identity["email"],
                    display_name=identity.get("display_name"),
                    auth_provider=provider,
                    provider_user_id=identity["provider_user_id"],
                )
                db.add(user)
            else:
                user.auth_provider = provider
                user.provider_user_id = identity["provider_user_id"]
            db.commit()
            db.refresh(user)

        if not user.is_active:
            log_activity(db, EventType.OAUTH_LOGIN_FAILED, user_id=user.id, ip_address=ip, user_agent=ua, detail="account inactive")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been deactivated.")

        from opsec_platform.app.security import create_session_token

        session_id = str(uuid.uuid4())
        token, expires_at = create_session_token(user.id, session_id, user.email)
        db.add(SessionModel(id=session_id, user_id=user.id, expires_at=expires_at, ip_address=ip, user_agent=ua))
        user.last_login_at = datetime.now(timezone.utc)
        db.commit()

        log_activity(db, EventType.OAUTH_LOGIN_SUCCESS, user_id=user.id, ip_address=ip, user_agent=ua, detail=provider)

        response = Response(status_code=302, headers={"Location": "/"})
        response.set_cookie(
            SESSION_COOKIE_NAME, token,
            httponly=True, samesite="lax", secure=settings.cookie_secure,
            max_age=int((expires_at - datetime.now(timezone.utc)).total_seconds()),
        )
        return response
    finally:
        db.close()
